/* mxdrivers エミュ（旧 boot/mxdrivers/devices.js + micetools 準拠）。
 * columba(SEGA DMI 読取→RINGEDGE2 board type), mxsram, mxsuperio(HWMON W83791D), mxsmbus(AT24C64AN eeprom),
 * mxhwreset。CreateFile→擬似ハンドル、DeviceIoControl→各応答（未知は ゼロ埋め+成功）。
 *
 * amBackup 記録は実 RingEdge では二デバイスに分かれる（nrs.exe amBackup_getAreaDescriptor board type 3 で確認）:
 *   - area 0,1 = EEPROM(AT24C64AN, mxsmbus 経由 IOCTL 0x9c40200c cmd8/9, dev 0x57) → g_eeprom
 *   - area 2,3 = SRAM  (mxsram 経由 SetFilePointer + ReadFile/WriteFile)            → g_sram
 * mxsram.sys は \Device\memcard0 を ByteOffset で R/W する wrapper。本エミュは nvram.bin に memory-map して
 * 永続化（micetools mxsram.c の open_mapped_file 方式に相当）。eeprom も eeprom.bin に永続。 */
#include "driver/mxdevices.h"
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
#include <wctype.h>

#define H_COLUMBA   ((HANDLE)(uintptr_t)0xD0000001u)
#define H_MXSRAM    ((HANDLE)(uintptr_t)0xD0000002u)
#define H_MXSUPERIO ((HANDLE)(uintptr_t)0xD0000003u)
#define H_MXSMBUS   ((HANDLE)(uintptr_t)0xD0000004u)
#define H_MXHWRESET ((HANDLE)(uintptr_t)0xD0000005u)

/* ---- DMI（micetools dmi.c RINGEDGE2 を移植） ---- */
#pragma pack(push, 1)
typedef struct { uint8_t Type, Length; uint16_t Handle; } DMI_SECHDR;
typedef struct { char Sig[5]; uint8_t Checksum; uint16_t StructLength; uint32_t StructAddr;
                 uint16_t NumberOfStructs; uint8_t BCDRevision, Reserved; } DMI_HEADER;
typedef struct { DMI_SECHDR Head; uint8_t Vendor, Version; uint16_t StartSegment;
                 uint8_t ReleaseDate, ROMSize; uint64_t Chars;
                 uint8_t VerMajor, VerMinor, ECVerMajor, ECVerMinor; } DMI_BIOS;
typedef struct { DMI_SECHDR Head; uint8_t Manufacturer, ProductName, Version, Serial; } DMI_SYSTEM;
typedef struct { DMI_SECHDR Head; uint8_t NoStrings; } DMI_STRING;
#pragma pack(pop)

static uint8_t g_dmi[1024];
static uint16_t g_dmi_size;
static int g_built;

/* ---- nvram 永続バッキング（mxsram / eeprom） ----
 * host サービスの原 CreateFile（フック迂回）でファイルを開き memory-map する。マップは process 寿命で保持し、
 * 書込みは OS のページキャッシュ経由で遅延永続化される（明示 flush 不要）。reload を跨いで生存（host 所有の
 * 原関数 + 一度きりの map）。フック迂回が必須: bind/IO は host のロック下で呼ばれるため、フック版 CreateFile を
 * 呼ぶと SRW ロック再入で deadlock する（facts/bugs.md の self-deadlock と同種）。 */
#define SRAM_BYTES   0x200000u   /* amSramInit が geometry(256*2*8*512)から導く総容量と一致（bounds 整合）*/
#define EEPROM_BYTES 8192u       /* AT24C64AN 8KiB */

static HostServices *g_host;
static uint8_t *g_sram;          /* mxsram 記録領域（nvram.bin にマップ or フォールバック）*/
static DWORD    g_sram_ptr;      /* SetFilePointer 位置（バイト, FILE_BEGIN 基準）*/
static uint8_t *g_eeprom;        /* AT24C64AN 記録（eeprom.bin にマップ or フォールバック）*/

typedef HANDLE (WINAPI *CreateFileW_fn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

/* name を bytes サイズで開き memory-map。新規ファイルは fill で初期化。失敗時 NULL。 */
static uint8_t *map_nvram(const wchar_t *name, DWORD bytes, uint8_t fill) {
    CreateFileW_fn cf = g_host ? (CreateFileW_fn)g_host->orig(ORIG_CREATE_FILE_W) : 0;
    if (!cf) return 0;
    HANDLE f = cf(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0,
                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz; sz.QuadPart = 0; GetFileSizeEx(f, &sz);
    int is_new = sz.QuadPart < (LONGLONG)bytes;
    HANDLE m = CreateFileMappingW(f, 0, PAGE_READWRITE, 0, bytes, 0);  /* ファイルを bytes へ伸張 */
    uint8_t *p = m ? (uint8_t *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, bytes) : 0;
    if (p && is_new) memset(p, fill, bytes);   /* 新規＝ブランク NVRAM（0xff）*/
    /* f/m は map 寿命のため意図的に閉じない（process 終了で解放）。CloseHandle はフック版でロック再入の危険。*/
    return p;
}

/* blank NVRAM = 0xff（CRC 不一致でゲームが既定値を書き直す。micetools build_sram と同じ）。 */
static void sram_ensure(void) {
    static uint8_t fallback_sram[SRAM_BYTES];
    if (g_sram) return;
    g_sram = map_nvram(L"nvram.bin", SRAM_BYTES, 0xff);
    if (!g_sram) { g_sram = fallback_sram; memset(g_sram, 0xff, SRAM_BYTES); }  /* 非永続フォールバック */
    if (g_host && g_host->log)
        g_host->log("info", "{\"ev\":\"mxsram.backing\",\"file\":\"nvram.bin\",\"bytes\":2097152}");
}
static void eeprom_ensure(void) {
    static uint8_t fallback_eeprom[EEPROM_BYTES];
    if (g_eeprom) return;
    g_eeprom = map_nvram(L"eeprom.bin", EEPROM_BYTES, 0xff);
    if (!g_eeprom) { g_eeprom = fallback_eeprom; memset(g_eeprom, 0xff, EEPROM_BYTES); }
}

void mxdev_init(HostServices *host) { g_host = host; }   /* map は初回 IO で遅延生成（bind 中の reload 安全）*/

HANDLE mxdev_smbus_handle(void) { return H_MXSMBUS; }    /* eeprom 強制 provisioning の device handle 用 */

static void d_append(const void *data, int size, int n, ...) {
    memcpy(g_dmi + g_dmi_size, data, size); g_dmi_size += (uint16_t)size;
    va_list ap; va_start(ap, n);
    for (int i = 0; i < n; i++) {
        const char *s = va_arg(ap, const char *);
        int l = (int)strlen(s);
        memcpy(g_dmi + g_dmi_size, s, l + 1); g_dmi_size += (uint16_t)(l + 1);
    }
    va_end(ap);
    g_dmi[g_dmi_size++] = 0;   /* セクション終端の二重 null（最後の文字列 null + これ）*/
}

static void build_dmi(void) {
    DMI_BIOS bios = { {0, 0x12, 0x0000}, 1, 2, 0x0000, 3, 0x00, 0x1f, 0x08, 0x0f, 0xff, 0xff };
    DMI_SYSTEM sys = { {1, 0x08, 0x0001}, 1, 2, 3, 4 };
    DMI_STRING str = { {11, 0x05, 0x0002}, 5 };
    g_dmi_size = 0;
    d_append(&bios, sizeof bios, 3, "American Megatrends Inc.", "080015 ", "07/28/2011");
    /* RINGEDGE2: manufacturer="NEC" */
    d_append(&sys, sizeof sys, 4, "NEC", "To Be Filled By O.E.M.",
             "To Be Filled By O.E.M.", "To Be Filled By O.E.M.");
    /* OEM strings RINGEDGE2: 0,1,PlatformId,3,BoardType */
    d_append(&str, sizeof str, 5, "DAC-BJ02", "DAC-BJ02", "AAL", "Advantech", "AAL2");
    g_built = 1;
}

/* ---- name 分類 ---- */
static int wcontains(const wchar_t *hay, const wchar_t *needle_lower) {
    wchar_t buf[300]; int i;
    if (!hay) return 0;
    for (i = 0; hay[i] && i < 299; i++) buf[i] = (wchar_t)towlower(hay[i]);
    buf[i] = 0;
    return wcsstr(buf, needle_lower) != 0;
}

int mxdev_create(const wchar_t *name, HANDLE *out) {
    if (!name) return 0;
    if (wcontains(name, L"columba"))   { *out = H_COLUMBA;   return 1; }
    if (wcontains(name, L"mxsram"))    { *out = H_MXSRAM;    return 1; }
    if (wcontains(name, L"mxsuperio")) { *out = H_MXSUPERIO; return 1; }
    if (wcontains(name, L"mxsmbus"))   { *out = H_MXSMBUS;   return 1; }
    if (wcontains(name, L"mxhwreset")) { *out = H_MXHWRESET; return 1; }
    return 0;
}

static int w83791d_bank = 0;

BOOL mxdev_ioctl(HANDLE h, DWORD code, void *in, DWORD inlen,
                 void *out, DWORD outlen, DWORD *ret, int *handled) {
    uint8_t *ib = (uint8_t *)in, *ob = (uint8_t *)out;
    *handled = 1;

    if (h == H_COLUMBA) {
        if (!g_built) build_dmi();
        if (code == 0x9c406104 && ib && ob) {        /* IOCTL_COLUMBA_READ */
            uint32_t physLo = *(uint32_t *)ib;
            uint32_t esz = *(uint32_t *)(ib + 8), ecnt = *(uint32_t *)(ib + 0xc);
            DWORD z = outlen < 0x10000 ? outlen : 0x10000;
            memset(ob, 0, z);
            if (physLo == 0x000f0000) {              /* DMI header */
                DMI_HEADER d; memset(&d, 0, sizeof d);
                memcpy(d.Sig, "_DMI_", 5);
                d.StructLength = g_dmi_size; d.StructAddr = 0x000f1000;
                d.NumberOfStructs = 0x20;
                if (outlen >= sizeof d) memcpy(ob, &d, sizeof d);
                if (ret) *ret = esz * ecnt;
                return TRUE;
            } else if (physLo == 0x000f1000) {        /* DMI tables */
                if (outlen >= g_dmi_size) memcpy(ob, g_dmi, g_dmi_size);
                if (ret) *ret = 0x10000;
                return TRUE;
            }
        }
        return FALSE;   /* unmapped/未知 */
    }

    if (h == H_MXSRAM) {
        if (code == 0x9c406000) { if (ob && outlen >= 4) *(uint32_t *)ob = 0x01000001; if (ret) *ret = 4; return TRUE; }
        /* IOCTL_MXSRAM_GET_SECTOR_SIZE: RINGEDGE2=4（micetools `MICE_PLATFORM_RINGEDGE2 ? 4 : 512` の authoritative 値。
           実 mxsram.sys はこの IOCTL を memcard0 へ転送＝ハード本来の粒度）。amSram(0x985DD0/0x985FF0)はこの値で
           記録の address/length のアラインメント(剰余=0)を検査する。SRAM 系 4 record は実体では全て 512B/512境界
           なので 512 でも通るが、authoritative かつ厳密に緩い 4 を返す。geometry の BytesPerSector=512(総容量計算用)とは別物。 */
        if (code == 0x9c406004) { if (ob && outlen >= 4) *(uint32_t *)ob = 4;          if (ret) *ret = 4; return TRUE; }
        if (code == 0x00070000) {                    /* IOCTL_DISK_GET_DRIVE_GEOMETRY */
            if (ob && outlen >= 24) {
                memset(ob, 0, 24);
                *(uint32_t *)(ob + 0) = 256; *(uint32_t *)(ob + 8) = 12;
                *(uint32_t *)(ob + 12) = 2; *(uint32_t *)(ob + 16) = 8; *(uint32_t *)(ob + 20) = 512;
            }
            if (ret) *ret = 24; return TRUE;
        }
        return FALSE;
    }

    if (h == H_MXSMBUS) {
        if (code == 0x9c406008) { if (ob && outlen >= 4) *(uint32_t *)ob = 0x01020001; if (ret) *ret = 4; return TRUE; }
        if ((code == 0x9c40200c || code == 0x9c402004) && ib && ob) {
            int i2c = (code == 0x9c40200c);
            uint8_t cmd = ib[1], vaddr, vcode, nb, off;
            if (i2c) { vaddr = (uint8_t)(*(uint16_t *)(ib + 2) & 0x7fff); vcode = (uint8_t)*(uint16_t *)(ib + 4); nb = ib[6]; off = 7; }
            else     { vaddr = ib[2] & 0x7f; vcode = ib[3]; nb = ib[4]; off = 5; }
            ob[0] = 0;   /* status ok */
            if (vaddr == 0x57) {                      /* AT24C64AN eeprom */
                eeprom_ensure();
                if (cmd == 9) { for (int k = 0; k < nb && (vcode + k) < (int)EEPROM_BYTES && (off + k) < (int)outlen; k++) ob[off + k] = g_eeprom[vcode + k]; }
                else if (cmd == 8) { for (int k = 0; k < nb && (vcode + k) < (int)EEPROM_BYTES; k++) g_eeprom[vcode + k] = ib[off + k]; }
                else if (off < (int)outlen) ob[off] = 0;
            }
            else if (cmd == 5) {                      /* amDipswReadByteInternal(off1=5, off3=index): dipsw read */
                if (off < (int)outlen) ob[off] = (vcode == 0) ? 0x20 : 0x00;  /* index0=0x20 → board index (0x20>>4)&7=2 / 他=0 */
            }
            if (ret) *ret = outlen;
            return TRUE;
        }
        return FALSE;
    }

    if (h == H_MXSUPERIO) {
        if (ob && outlen > 0 && outlen <= 4096) memset(ob, 0, outlen);
        if (code == 0x9c406000) { if (ob && outlen >= 4) *(uint32_t *)ob = 0x01000001; }
        else if (code == 0x9c40200c && ib && inlen >= 3 && ob && outlen >= 3) {
            uint8_t idx = ib[0], reg = ib[1], data = 0;
            if (w83791d_bank == 0) {
                switch (reg) { case 0x58: data=0x71; break; case 0x4F: data=0xa3; break; case 0x48: data=0x11; break;
                    case 0x4E: data=0x00; break; case 0x40: data=0x01; break; case 0x27: data=26; break;
                    case 0x20: data=0x76; break; case 0x21: data=0x86; break; case 0x23: data=0x94; break;
                    case 0x24: data=0xbe; break; case 0x25: data=0xd1; break; case 0x47: data=0x05; break; }
            } else if (w83791d_bank == 1) {
                if (reg == 0x50) data = 35; else if (reg == 0x51) data = 0x07;
            }
            ob[0] = idx; ob[1] = reg; ob[2] = data;
        } else if (code == 0x9c40a010 && ib && inlen >= 3) {
            if (ib[1] == 0x4E) w83791d_bank = ib[2] & 0x07;
        }
        if (ret) *ret = (outlen <= 4096) ? outlen : 0;
        return TRUE;
    }

    if (h == H_MXHWRESET) {
        if (ob && outlen > 0 && outlen <= 4096) memset(ob, 0, outlen);
        if (ret) *ret = (outlen <= 4096) ? outlen : 0;
        return TRUE;
    }

    *handled = 0;
    return FALSE;
}

/* ---- mxsram データ面（SetFilePointer + ReadFile/WriteFile） ----
 * 実 RingEdge: amSram が SetFilePointer(handle, recordAddr, FILE_BEGIN) で位置決めし ReadFile/WriteFile で
 * 記録を授受。mxsram.sys は ByteOffset で memcard0 を R/W する。単一ハンドル・mutex 直列前提なのでポインタは
 * グローバル一本で足りる（amSram は 1 度だけ open し、primary/dup を seek→IO で逐次アクセス）。 */
DWORD mxdev_seek(HANDLE h, long dist, long *dist_high, DWORD method, int *handled) {
    if (h != H_MXSRAM) { *handled = 0; return INVALID_SET_FILE_POINTER; }
    *handled = 1;
    long long base = (method == FILE_CURRENT) ? (long long)g_sram_ptr
                   : (method == FILE_END)     ? (long long)SRAM_BYTES
                   :                            0;                       /* FILE_BEGIN */
    long long np = base + dist;
    if (np < 0) np = 0;
    if (np > (long long)SRAM_BYTES) np = SRAM_BYTES;
    g_sram_ptr = (DWORD)np;
    if (dist_high) *dist_high = 0;
    return g_sram_ptr;
}

BOOL mxdev_read(HANDLE h, void *buf, DWORD n, DWORD *got, int *handled) {
    if (h != H_MXSRAM) { *handled = 0; return FALSE; }
    *handled = 1;
    sram_ensure();
    if (g_sram_ptr > SRAM_BYTES) g_sram_ptr = SRAM_BYTES;
    DWORD avail = SRAM_BYTES - g_sram_ptr;
    DWORD k = n < avail ? n : avail;
    if (buf && k) memcpy(buf, g_sram + g_sram_ptr, k);
    g_sram_ptr += k;
    if (got) *got = k;
    return TRUE;
}

BOOL mxdev_write(HANDLE h, const void *buf, DWORD n, DWORD *put, int *handled) {
    if (h != H_MXSRAM) { *handled = 0; return FALSE; }
    *handled = 1;
    sram_ensure();
    if (g_sram_ptr > SRAM_BYTES) g_sram_ptr = SRAM_BYTES;
    DWORD avail = SRAM_BYTES - g_sram_ptr;
    DWORD k = n < avail ? n : avail;
    if (buf && k) memcpy(g_sram + g_sram_ptr, buf, k);  /* mmap が遅延永続化 */
    g_sram_ptr += k;
    if (put) *put = k;
    return TRUE;
}
