/* Fixed hosted automatic-ID2 association control; no CRT or runtime input. */
typedef unsigned long u32;
typedef unsigned short u16;
typedef unsigned __int64 usize;
#define API __declspec(dllimport)
#define CALL __stdcall
#define OFFSET(type, member) ((usize)&(((type *)0)->member))
struct Observation {
    u32 size, attach, query, evaluated, ownRoot, error, returned, assemblies;
};
typedef char RecordSize[(sizeof(struct Observation) == 32 && OFFSET(struct Observation, error) == 20 && OFFSET(struct Observation, assemblies) == 28) ? 1 : -1];
typedef char PointerSize[(sizeof(void *) == 8 && sizeof(u16) == 2 && sizeof(u32) == 4) ? 1 : -1];

#ifdef MODULE_DLL
struct Detail {
    u32 flags, version, assemblies, rootType, rootChars, configType, configChars, dirType, dirChars;
    const u16 *root, *config, *dir;
};
typedef char DetailSize[(sizeof(struct Detail) == 64) ? 1 : -1];
typedef char RootOffset[(OFFSET(struct Detail, root) == 40) ? 1 : -1];
API int CALL QueryActCtxW(u32, void *, void *, u32, void *, usize, usize *);
API u32 CALL GetLastError(void);
API u32 CALL GetModuleFileNameW(void *, u16 *, u32);
API int CALL CompareStringOrdinal(const u16 *, int, const u16 *, int, int);
static void *ownModule;
static volatile u32 attaches;
static union { usize align; unsigned char bytes[65536]; } storage;
static u16 modulePath[1024], hostPath[1024];
static int DetailValid(unsigned char *, usize, const u16 **, u32 *);
static int TextValid(const u16 *, u32);

static int SelfCheck(void)
{
    union { usize align; unsigned char bytes[128]; } fixture;
    u32 i;
    struct Detail *d = (struct Detail *)fixture.bytes;
    u16 *text = (u16 *)(fixture.bytes + 64);
    const u16 *root = 0;
    u32 chars = 0;
    for (i = 0; i < sizeof(fixture.bytes); i++) fixture.bytes[i] = 0;
    d->version = 1; d->assemblies = 1; d->rootType = 2; d->rootChars = 3; d->root = text;
    text[0] = 'A'; text[1] = ':'; text[2] = '\\'; text[3] = 0;
    if (!DetailValid(fixture.bytes, 72, &root, &chars) || root != text || chars != 3) return 0;
    d->flags = 1; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; d->flags = 0;
    d->version = 2; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; d->version = 1;
    d->rootType = 3; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; d->rootType = 2;
    d->assemblies = 0; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; d->assemblies = 1;
    d->assemblies = 17; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; d->assemblies = 1;
    d->root = 0; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    d->root = (const u16 *)(fixture.bytes + 65); if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    d->root = (const u16 *)(fixture.bytes + 62); if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    d->root = (const u16 *)(fixture.bytes + 72); if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    d->root = (const u16 *)(usize)-2; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    d->root = text; d->rootChars = 1024; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    d->rootChars = 0xffffffffUL; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; d->rootChars = 3;
    text[3] = 'X'; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; text[3] = 0;
    text[1] = 0; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; text[1] = ':';
    text[1] = 0xd800; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    text[1] = 0xdc00; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    text[1] = 0xd800; text[2] = 0xdc00;
    if (!DetailValid(fixture.bytes, 72, &root, &chars)) return 0;
    text[1] = ':'; text[2] = '\\';
    d->configChars = 1; if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; d->configChars = 0;
    d->dir = (const u16 *)(fixture.bytes + 72); if (DetailValid(fixture.bytes, 72, &root, &chars)) return 0; d->dir = 0;
    if (DetailValid(fixture.bytes, 63, &root, &chars) || DetailValid(fixture.bytes, 65537, &root, &chars)) return 0;
    d->root = 0; d->rootChars = 0; d->rootType = 0; d->version = 0; d->assemblies = 0;
    if (!DetailValid(fixture.bytes, 64, &root, &chars) || root || chars) return 0;
    text[0] = 0; d->root = text;
    if (!DetailValid(fixture.bytes, 66, &root, &chars) || root != text || chars) return 0;
    return 1;
}
static int TextValid(const u16 *text, u32 chars)
{
    u32 i;
    if (chars > 1023 || !text || text[chars]) return 0;
    for (i = 0; i < chars; i++) {
        u16 c = text[i];
        if (!c) return 0;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (++i >= chars || text[i] < 0xdc00 || text[i] > 0xdfff) return 0;
        } else if (c >= 0xdc00 && c <= 0xdfff) return 0;
    }
    return 1;
}
static int SpanText(unsigned char *buffer, usize size, const u16 *pointer, u32 chars)
{
    usize start = (usize)buffer, address = (usize)pointer, offset, bytes;
    if (!pointer) return chars == 0;
    if ((address & 1) || address < start || chars > 1023) return 0;
    offset = address - start; bytes = ((usize)chars + 1) * 2;
    if (offset < 64 || offset > size || bytes > size - offset) return 0;
    return TextValid(pointer, chars);
}
static int DetailValid(unsigned char *buffer, usize size, const u16 **root, u32 *chars)
{
    struct Detail *d;
    if (size < 64 || size > 65536) return 0;
    d = (struct Detail *)buffer;
    if (d->flags || d->version > 1 || d->assemblies > 16 || d->rootType > 4 || d->configType > 4 || d->dirType > 4) return 0;
    if (!SpanText(buffer, size, d->root, d->rootChars) || !SpanText(buffer, size, d->config, d->configChars) ||
        !SpanText(buffer, size, d->dir, d->dirChars)) return 0;
    if (d->rootChars && (d->version != 1 || !d->assemblies || d->rootType != 2)) return 0;
    *root = d->root; *chars = d->rootChars;
    return 1;
}
int CALL ModuleEntry(void *module, u32 reason, void *reserved)
{
    (void)reserved;
    if (reason == 1) { ownModule = module; attaches++; }
    return 1;
}
static int Observe(struct Observation *out)
{
    const u16 *root;
    const u16 basename[] = { 's','t','a','r','t','u','p','-','m','o','d','u','l','e','.','d','l','l',0 };
    usize required = 0;
    u32 length, hostLength, moduleLength, directory;
    int query, compared;
    if (!out || out->size != 32 || attaches != 1 || !ownModule || !SelfCheck()) return 0;
    out->attach = 1;
    query = QueryActCtxW(8, ownModule, 0, 2, storage.bytes, sizeof(storage.bytes), &required);
    out->error = query ? 0 : GetLastError();
    if (required > 65536 || (!query && !out->error)) return 0;
    out->query = query ? 1 : 0; out->returned = (u32)required;
    if (query) {
        if (!DetailValid(storage.bytes, required, &root, &length)) return 0;
        out->assemblies = ((struct Detail *)storage.bytes)->assemblies;
    } else { root = 0; length = 0; }
    hostLength = GetModuleFileNameW(0, hostPath, 1024);
    moduleLength = GetModuleFileNameW(ownModule, modulePath, 1024);
    if (!hostLength || hostLength >= 1024 || !moduleLength || moduleLength >= 1024 ||
        !TextValid(hostPath, hostLength) || !TextValid(modulePath, moduleLength)) return 0;
    for (directory = hostLength; directory && hostPath[directory - 1] != '\\'; directory--) { }
    if (!directory || directory + 18 != moduleLength) return 0;
    compared = CompareStringOrdinal(hostPath, (int)directory, modulePath, (int)directory, 1);
    if (compared != 2 || CompareStringOrdinal(modulePath + directory, 18, basename, 18, 1) != 2) return 0;
    if (query && length) {
        compared = CompareStringOrdinal(root, (int)length, modulePath, (int)moduleLength, 1);
        if (compared < 1 || compared > 3) return 0;
        out->evaluated = 1; out->ownRoot = compared == 2;
    }
    return 1;
}
__declspec(dllexport) int CALL ObserveModuleActivation(struct Observation *out)
{
    u32 i;
    int result = Observe(out);
    for (i = 0; i < sizeof(storage.bytes); i++) storage.bytes[i] = 0;
    for (i = 0; i < 1024; i++) { modulePath[i] = 0; hostPath[i] = 0; }
    return result;
}
#else
API void * CALL GetStdHandle(u32);
API int CALL WriteFile(void *, const void *, u32, u32 *, void *);
API void CALL ExitProcess(u32);
API int CALL ObserveModuleActivation(struct Observation *);
static void Hex(char *line, u32 *position, u32 value)
{
    u32 i;
    for (i = 0; i < 8; i++) line[(*position)++] = "0123456789ABCDEF"[(value >> ((7 - i) * 4)) & 15];
}
#define APPEND(text) { u32 k; for (k = 0; k < sizeof(text) - 1; k++) line[position++] = text[k]; }
void CALL StartupEntry(void)
{
    struct Observation observed;
    char line[256];
    u32 i, position = 0, written = 0;
    void *output;
    for (i = 0; i < sizeof(observed); i++) ((unsigned char *)&observed)[i] = 0;
    observed.size = 32;
    if (!ObserveModuleActivation(&observed) || observed.size != 32 || observed.attach != 1 || observed.query > 1 ||
        observed.evaluated > 1 || observed.ownRoot > 1 || observed.returned > 65536 || observed.assemblies > 16 ||
        (observed.query && (observed.error || observed.returned < 64)) || (!observed.query && (!observed.error || observed.evaluated || observed.ownRoot || observed.assemblies)) ||
        (observed.ownRoot && !observed.evaluated)) ExitProcess(121);
    APPEND("WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded="); line[position++] = '0' + (char)observed.query;
    APPEND(" root_evaluated="); line[position++] = '0' + (char)observed.evaluated;
    APPEND(" root_is_module="); line[position++] = '0' + (char)observed.ownRoot;
    APPEND(" win32_error=0x"); Hex(line, &position, observed.error);
    APPEND(" returned_bytes=0x"); Hex(line, &position, observed.returned);
    APPEND(" assembly_count=0x"); Hex(line, &position, observed.assemblies);
    APPEND("\n");
    output = GetStdHandle((u32)-11);
    if (position > sizeof(line) || !output || output == (void *)-1 || !WriteFile(output, line, position, &written, 0) || written != position) ExitProcess(121);
    ExitProcess(0);
}
#endif
