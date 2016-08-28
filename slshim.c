#define CryptGetHashParam CryptGetHashParam_dummy
#include <windows.h>
#include <stdint.h>
#include <winternl.h>
#include <stdio.h>
#include <ntstatus.h>
#include <shlwapi.h>
#undef CryptGetHashParam

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define malloc(n) LocalAlloc(LMEM_ZEROINIT, n)
#define SL_E_VALUE_NOT_FOUND 	0xC004F012
#define SL_E_NOT_SUPPORTED 	0xC004F016

typedef DWORD SLDATATYPE;
typedef GUID SLID;
typedef DWORD SLIDTYPE;
#define DEADBEEF 0xdeadbeef
#define APP "SYSTEM\\Tokens"
#define KERNEL "SYSTEM\\Tokens\\Kernel"

#define POL_MAX 1024

// Policy header
typedef struct {
	ULONG 	sz; 		// Size of everything.
	ULONG 	data_sz; 	// Always sz-0x18.
	ULONG 	endpad; 	// End padding. Usually 4.
	ULONG 	tainted; 	// 1 if tainted.
	ULONG 	pad1; 		// Always 1
} __attribute((packed)) pol_hdr;

// Policy entry
typedef struct {
	USHORT  sz; 		// Size of whole entry.
	USHORT 	name_sz; 	// Size of the following field, in bytes.
	USHORT 	type; 		// Field type
	USHORT 	data_sz; 	// Field size
	ULONG 	flags; 		// Field flags
	ULONG 	pad0; 		// Always 0
	UCHAR 	name[0]; 	// WCHAR name, NOT zero terminated!
} __attribute__((packed)) pol_ent;

typedef struct {
	SLID              SkuId;
	DWORD 		  eStatus;
	DWORD             dwGraceTime;
	DWORD             dwTotalGraceDays;
	HRESULT           hrReason;
	UINT64            qwValidityExpiration;
} SL_LICENSING_STATUS;

#define	F_INVALID		0x01
#define F_PREFIX		0x02
#define	F_REX			0x04
#define F_MODRM			0x08
#define F_SIB			0x10
#define F_DISP			0x20
#define F_IMM			0x40
#define F_RELATIVE		0x80
#define OP_NONE			0x00
#define OP_INVALID		0x80

#define OP_DATA_I8		0x01
#define OP_DATA_I16		0x02
#define OP_DATA_I16_I32		0x04
#define OP_DATA_I16_I32_I64	0x08
#define OP_EXTENDED		0x10
#define OP_RELATIVE		0x20
#define OP_MODRM		0x40
#define OP_PREFIX		0x80

typedef struct {
	BYTE		flags;
	BYTE		rex;
	BYTE		modrm;
	BYTE		sib;
	BYTE		opcd_offset;
	BYTE		opcd_size;
	BYTE		disp_offset;
	BYTE		disp_size;
	BYTE		imm_offset;
	BYTE		imm_size;
} ldasm_data;


// ripped from libsplice, trimmed and fixed w8+ DEP+virtualprotect bugs
static const uint64_t us1[32]={0x0000040140404040ULL, 0x0000040140404040ULL,
        0x0000040140404040ULL, 0x0000040140404040ULL, 0x0080040140404040ULL,
        0x0080040140404040ULL, 0x0080040140404040ULL, 0x0080040140404040ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x8080808040400000ULL, 0x0000000041014404ULL,
        0x2121212121212121ULL, 0x2121212121212121ULL, 0x4040404041414441ULL,
        0x4040404040404040ULL, 0x0000000000000000ULL, 0x0000000000060000ULL,
        0x0000000008010801ULL, 0x0000000000000401ULL, 0x0101010101010101ULL,
        0x0808080808080808ULL, 0x4441404000024141ULL, 0x0000010000020003ULL,
        0x0000010140404040ULL, 0x4040404040404040ULL, 0x0101010121212121ULL,
        0x0000000021062424ULL, 0x4040000080800080ULL, 0x4040000000000000ULL};
static const uint64_t us2[32]={0x0000008040404040ULL, 0x4180408000800000ULL,
        0x4040404040404040ULL, 0x0080808080808040ULL, 0x8040805040404040ULL,
        0x4040404040404040ULL, 0x0080000000000000ULL, 0x8080808080518050ULL,
        0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL,
        0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL,
        0x0040404041414141ULL, 0x4040404080804040ULL, 0x2424242424242424ULL,
        0x2424242424242424ULL, 0x4040404040404040ULL, 0x4040404040404040ULL,
        0x8080404140000000ULL, 0x4040404140000000ULL, 0x4040404040404040ULL,
        0x4040404040414040ULL, 0x4041414140414040ULL, 0x0000000000000000ULL,
        0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL,
        0x4040404040404040ULL, 0x4040404040404040ULL, 0x8040404040404040ULL};

#ifdef _WIN64
#define SPLICE_SIZE			14
#define set_jump(_src,_dst) *((ULONG_PTR*)_src) = 0x25FF; *((ULONG_PTR*)((_src)+6)) = (ULONG_PTR)(_dst)
#else
#define SPLICE_SIZE			5
#define set_jump(_src,_dst) *((BYTE*)(_src)) = 0xE9; *((ULONG_PTR*)((_src)+1)) = (DWORD)(_dst) - (DWORD)(_src) - 5
#endif

static unsigned char cflags(BYTE op)
{
	return ((BYTE*)us1)[op];
}


static unsigned char cflags_ex(BYTE op)
{
	return ((BYTE*)us2)[op];
}

static unsigned int ldasm(void *code, ldasm_data *ld, DWORD is64)
/*
 Description:
 Disassemble one instruction
 
 Arguments: 
 code	- pointer to the code for disassemble
 ld		- pointer to structure ldasm_data
 is64	- set this flag for 64-bit code, and clear for 32-bit
 
 Return:
 length of instruction
 */
{
	BYTE *p = code;
	BYTE s,op,f;
	BYTE rexw,pr_66,pr_67;
	
	s = rexw = pr_66 = pr_67 = 0;
	
	/* dummy check */
	if (!code || !ld)
		return 0;
	
	/* init output data */
	memset(ld,0,sizeof(ldasm_data));
	
	/* phase 1: parse prefixies */
	while (cflags(*p) & OP_PREFIX) {
		if (*p == 0x66) 
			pr_66 = 1;
		if (*p == 0x67) 
			pr_67 = 1;
		p++; s++;
		ld->flags |= F_PREFIX;
		if (s == 15) {
			ld->flags |= F_INVALID;
			return s;
		}
	}
	
	/* parse REX prefix */
	if (is64 && *p >> 4 == 4) {
		ld->rex = *p;
		rexw = (ld->rex >> 3) & 1;
		ld->flags |= F_REX;
		p++; s++;
	}
	
	/* can be only one REX prefix */
	if (is64 && *p >> 4 == 4) {
		ld->flags |= F_INVALID;
		s++;
		return s;
	}
	
	/* phase 2: parse opcode */
	ld->opcd_offset = (BYTE)(p - (BYTE*)code);
	ld->opcd_size	= 1;
	op = *p++; s++;
	
	/* is 2 byte opcede? */
	if (op == 0x0F) {
		op = *p++; s++;
		ld->opcd_size++;
		f = cflags_ex(op);
		if (f & OP_INVALID){
			ld->flags |= F_INVALID;
			return s;
		}
		/* for SSE instructions */
		if (f & OP_EXTENDED) {
			op = *p++; s++;
			ld->opcd_size++;
		}
	} else {
		f = cflags(op);
		/* pr_66 = pr_67 for opcodes A0-A3 */
		if (op >= 0xA0 && op <= 0xA3)
			pr_66 = pr_67;
	}
	
	/* phase 3: parse ModR/M, SIB and DISP */
	if (f & OP_MODRM) {
		BYTE	mod = (*p >> 6);
		BYTE	ro	= (*p & 0x38) >> 3;  
		BYTE	rm  = (*p & 7);
		
		ld->modrm = *p++; s++;
		ld->flags |= F_MODRM;
		
		/* in F6,F7 opcodes immediate data present if R/O == 0 */
		if (op == 0xF6 && (ro == 0 || ro == 1)) 
			f |= OP_DATA_I8;    
		if (op == 0xF7 && (ro == 0 || ro == 1))
			f |= OP_DATA_I16_I32_I64; 
		
		/* is SIB byte exist? */
		if (mod != 3 && rm == 4 && !(!is64 && pr_67)) {
			ld->sib = *p++; s++;
			ld->flags |= F_SIB;
			
			/* if base == 5 and mod == 0 */
			if ((ld->sib & 7) == 5 && mod == 0) {
				ld->disp_size = 4;
			}
		}
		
		switch (mod) {
			case 0:
				if (is64) {
					if (rm == 5) {
						ld->disp_size = 4;
						if (is64)
							ld->flags |= F_RELATIVE;
					}
				} else if (pr_67) {
					if (rm == 6) 
						ld->disp_size = 2;
				} else {
					if (rm == 5) 
						ld->disp_size = 4;
				}
				break;
			case 1:
				ld->disp_size = 1;
				break;
			case 2:
				if (is64)
					ld->disp_size = 4;
				else if (pr_67)
					ld->disp_size = 2;
				else
					ld->disp_size = 4;
				break;
		}
		
		if (ld->disp_size) {
			ld->disp_offset = (BYTE)(p - (BYTE *)code);
			p += ld->disp_size;
			s += ld->disp_size;
			ld->flags |= F_DISP;
		}
	}
	
	/* phase 4: parse immediate data */
	if (rexw && f & OP_DATA_I16_I32_I64)
		ld->imm_size = 8;
	else if (f & OP_DATA_I16_I32 || f & OP_DATA_I16_I32_I64) 
		ld->imm_size = 4 - (pr_66 << 1);
	
	/* if exist, add OP_DATA_I16 and OP_DATA_I8 size */
	ld->imm_size += f & 3;
	
	if (ld->imm_size) {
		s += ld->imm_size;
		ld->imm_offset = (BYTE)(p - (BYTE *)code);
		ld->flags |= F_IMM;
		if (f & OP_RELATIVE)
			ld->flags |= F_RELATIVE;
	}
	
	/* instruction is too long */
	if (s > 15)
		ld->flags |= F_INVALID;
	
	return s;
}

static inline void splice(void *proc, void *new_proc, void **old_proc)
{
	BYTE 			*src, *old;
	DWORD 			all_len = 0;
	DWORD			protect, dummy;
	ldasm_data		ld;

	/* alloc buffer for original code */
	*old_proc = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (!*old_proc)
		return;

	src = proc;
	old = *old_proc;

	if (!VirtualProtect(proc, SPLICE_SIZE, PAGE_EXECUTE_READWRITE, &protect))
		if (!VirtualProtect(proc, SPLICE_SIZE, PAGE_READWRITE, &protect))
			goto fail;

#ifdef _WIN64
	/* already hooked? */
	if (*((USHORT*)(src)) == 0x25FF && *((DWORD*)(src+2)) == 0) {

		/* set jump to previous hook */
		set_jump(old, *((ULONG_PTR*)(src+6)));
		
		/* replace jump address */
		*((ULONG_PTR*)(src+6)) = (ULONG_PTR)new_proc;
		goto out;
	}
#endif

	/* move first bytes of proc to the buffer */
	do {
		/* disasm instruction */
		DWORD len = ldasm(src, &ld, 1);
		/* check instruction */
		if (ld.flags & F_INVALID
			|| (len == 1 && (src[ld.opcd_offset] == 0xCC || src[ld.opcd_offset] == 0xC3))
			|| (len == 3 && src[ld.opcd_offset] == 0xC2)
			|| len + all_len + SPLICE_SIZE > PAGE_SIZE) {

			goto fail;
		}

		/* move opcode */
		memcpy(old, src, len);
#ifdef _WIN64
		/* if instruction has relative offset, calculate new offset */
		if (ld.flags & F_RELATIVE) {
			if (ld.opcd_size == 2) {
				if (_abs64((ULONG_PTR)(src + *((INT*)(old+1))) - (ULONG_PTR)old) > INT_MAX)
				/* if jump greater then 2GB offset exit */
					goto fail;
				else
					*((DWORD*)(old+2)) += (DWORD)(src - old);
			} else {
				if (_abs64((ULONG_PTR)(src + *((INT*)(old+1))) - (ULONG_PTR)old) > INT_MAX)
				/* if jump greater then 2GB offset exit */
					goto fail;
				else
					*((DWORD*)(old+1)) += (DWORD)(src - old);
			}
#else
		/* if instruction has relative offset, calculate new offset */
		if (ld.flags & F_RELATIVE) {
			if (ld.opcd_size == 2) {
				*((ULONG_PTR*)(old+2)) += (DWORD)(src - old);
			} else {
				*((ULONG_PTR*)(old+1)) += (DWORD)(src - old);
			}
#endif
		}

		src += len;
		old += len;
		all_len += len;
	} while (all_len < SPLICE_SIZE);

	/* set jump form spliced bytes to original code */
	set_jump(old, src);
	VirtualProtect(*old_proc, PAGE_SIZE, PAGE_EXECUTE, &dummy);

	src = proc;

	/* set jump form original code to new proc */
	set_jump(src, new_proc);
#ifdef _WIN64
out:;
#endif
	VirtualProtect(proc, SPLICE_SIZE, protect, &dummy);
	return;

fail:;
     	VirtualFree(*old_proc, PAGE_SIZE, MEM_RELEASE);
	*old_proc = NULL;
}

typedef void *HSLC, *HSLP;
static SLID consumed_skuids[256];
static int nconsumed;
// Ugly, ugly. But we have to. Callers often have tight stack limits.
// And doing malloc in DllMain is ... tricky as the buffer is unused
// more often than not - we get loaded multiple times. .bss is more likely
// to stay out of working set than malloc.
static DWORD tbuf[8192];

static HRESULT sl_get(const char *path, const WCHAR *name, SLDATATYPE *t, UINT *pcbValue, PBYTE *ppbValue)
{
	DWORD pop = 0;
	DWORD ot = 4;
	DWORD sz = sizeof(tbuf);
	HKEY k;

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k))
		return SL_E_VALUE_NOT_FOUND;

	RegQueryValueExW(k, L"Populate", 0, NULL, (BYTE*)&pop, &ot);

	if (pop) {
		HKEY k2;
		if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ|KEY_WRITE, &k2)) {
			RegCloseKey(k);
			k = k2;
		} else pop = 0;
	}

	int ret = RegQueryValueEx(k, name, 0, (DWORD*)&ot, (void*)&tbuf, (DWORD*)&sz);
	if (ret) {
		if (*name == L'*') {
			ret = S_OK;
			sz = 4;
			ot = REG_MULTI_SZ;
			tbuf[0] = 0;
		} else {
			sz = sizeof(tbuf);
			ret = SL_E_VALUE_NOT_FOUND;
			WCHAR valn[256];
			DWORD valnsz = 256;
			int best = -1;
			int bestlen = -1;
			for (int i = 0; (valnsz = sizeof(valn)/2) && !RegEnumValue(k, i, valn, &valnsz, 0, NULL, NULL, NULL); i++) {
				if (PathMatchSpec(name, valn)) {
					if (((int)valnsz) > bestlen) {
						bestlen = valnsz;
						best = i;
					}
				}
			}
			if (best == -1)
				goto out;
			valnsz = sizeof(valn)/2;
			if (RegEnumValue(k, best, valn, &valnsz, 0, &ot, (void*)tbuf, &sz))
				goto out;

			if (pop) 
				RegSetValueEx(k, name, 0, ot, (void*)tbuf, sz);
			ret = S_OK;
		}
	}
	if ((ot == REG_DWORD) && (tbuf[0] == DEADBEEF)) {
		ret = SL_E_VALUE_NOT_FOUND;
		goto out;
	}
	if ((!ret) && ((t == ((void*)-1)) && (pcbValue == ((void*)-1)))) {
		*((DWORD*)ppbValue) = tbuf[0];
		ret = S_OK;
		goto out;
	}

	if (ppbValue) {
		*ppbValue = LocalAlloc(0, sz);
		memcpy(*ppbValue, (void*)tbuf, sz);
	}
	if (pcbValue) *pcbValue = sz;
	if (t) *t = ot;
out:;
	RegCloseKey(k);
	return ret;
}


HRESULT WINAPI SLOpen(HSLC *out)
{
	*out = (void*)1;
	return S_OK;
}

HRESULT WINAPI SLGetApplicationInformation(
	HSLC       hSLC,
	SLID       *pApplicationId,
	PWSTR     pwszValueName,
	SLDATATYPE *peDataType,
	UINT       *pcbValue,
	PBYTE      *ppbValue
)
{
	return sl_get(APP, pwszValueName, peDataType, pcbValue, ppbValue);
}

HRESULT WINAPI SLGetGenuineInformation(
	const SLID 	*pAppId,
	PCWSTR 		pwszValueName,
	SLDATATYPE 	*peDataType,
	UINT 		*pcbValue,
	BYTE 		**ppbValue
)
{
	return sl_get(APP, pwszValueName, peDataType, pcbValue, ppbValue);
}
HRESULT WINAPI SLGetSLIDList(
	HSLC     hSLC,
	SLIDTYPE eQueryIdType,
	SLID     *pQueryId,
	SLIDTYPE eReturnIdType,
	UINT     *pnReturnIds,
	SLID     **ppReturnIds
)
{
	*ppReturnIds = malloc(sizeof(SLID) * nconsumed);
	memcpy((void*)*ppReturnIds, (void*)consumed_skuids, nconsumed * sizeof(SLID));
	*pnReturnIds = nconsumed;
	return S_OK;
}

HRESULT WINAPI SLInstallLicense(
	HSLC hSLC,
	UINT cbLicenseBlob,
	const BYTE *pbLicenseBlob,
	SLID *pLicenseFileId
)
{
	*pLicenseFileId = (SLID){0};
	return S_OK;
}

HRESULT WINAPI SLGetPKeyInformation(
	HSLC       hSLC,
	SLID       *pPKeyId,
	PWSTR     pwszValueName,
	SLDATATYPE *peDataType,
	UINT       *pcbValue,
	PBYTE      *ppbValue
)
{
	return sl_get(APP, pwszValueName, peDataType, pcbValue, ppbValue);
}


HRESULT WINAPI SLGetLicensingStatusInformation(
	HSLC                hSLC,
	SLID                *pAppID,
	SLID                *pProductSkuId,
	PWSTR               pwszRightName,
	UINT                *pnStatusCount,
	SL_LICENSING_STATUS **ppLicensingStatus
)
{
	SL_LICENSING_STATUS *entry = malloc(sizeof(SL_LICENSING_STATUS) * nconsumed);
	for (int i = 0; i < nconsumed; i++) {
		memcpy((void*)&entry[i].SkuId, (void*)&consumed_skuids[i], sizeof(SLID));
		entry[i].eStatus = 1;
	}
	*pnStatusCount = nconsumed;
	*ppLicensingStatus = entry;
	return S_OK;
}

HRESULT WINAPI SLGetPolicyInformation(
	HSLC                    hSLC,
	PWSTR                   pwszValueName,
	SLDATATYPE*             peDataType,
	UINT*                   pcbValue,
	PBYTE*            	ppbValue
)
{
	return sl_get(APP, pwszValueName, peDataType, pcbValue, ppbValue);
}

HRESULT WINAPI SLGetPolicyInformationDWORD(
	HSLC                        hSLC,
	PWSTR                      pwszValueName,
	DWORD*                      pdwValue
)
{
	return SLGetPolicyInformation(hSLC, pwszValueName, (void*)-1, (void*)-1, (PBYTE*)pdwValue);
}

HRESULT WINAPI SLIsGenuineLocal(
	const SLID 		*pAppId,
	DWORD 	*pGenuineState,
	void *pUIOptions
)
{
	*pGenuineState = 0;
	return S_OK;
}

HRESULT WINAPI SLConsumeRight(
	HSLC   hSLC,
	SLID   *pAppId,
	SLID   *pProductSkuId,
	PWSTR pwszRightName,
	PVOID  pvReserved
)
{
	// Try to look up by app id
	if (!pProductSkuId) {
		WCHAR buf[64];
		if (!pAppId)
			return SL_E_NOT_SUPPORTED;
		StringFromGUID2(pAppId, buf, 64);
		WCHAR *bufp = NULL;
		sl_get(APP, buf, NULL, NULL, (BYTE**)&bufp);
		if (bufp) {
			int i;
			for(i = 0; *bufp; bufp = bufp + wcslen(bufp)+1, i++) {
				CLSIDFromString(bufp, &consumed_skuids[i]);
			}
			nconsumed = i;
			LocalFree(bufp);
		}
	} else {
		memcpy((void*)&consumed_skuids, (void*)pProductSkuId, sizeof(SLID));
		nconsumed = 1;
	}
	return S_OK;
}

HRESULT WINAPI SLGetWindowsInformation(
	PCWSTR     pwszValueName,
	SLDATATYPE *peDataType,
	UINT       *pcbValue,
	PBYTE      *ppbValue
)
{
	__declspec(dllimport) NTSTATUS NTAPI NtQueryLicenseValue(PUNICODE_STRING,DWORD*,PVOID,DWORD,DWORD*);
	if (sl_get(KERNEL, pwszValueName, peDataType, pcbValue, ppbValue) == SL_E_VALUE_NOT_FOUND) {
		// todo - support deadbeef nukes
		UNICODE_STRING us;
		us.Buffer = (void*)pwszValueName;
		us.MaximumLength = (us.Length = wcslen(pwszValueName)*2)+2;
		ULONG sz = sizeof(tbuf);
		ULONG typ;
		if (!NT_SUCCESS(NtQueryLicenseValue(&us, &typ, tbuf, sizeof(tbuf), &sz)))
			return SL_E_VALUE_NOT_FOUND;
		if (pcbValue == (void*)-1) {
			*((DWORD*)ppbValue) = tbuf[0];
			return S_OK;
		}
		if (peDataType)
			*peDataType = typ;
		if (pcbValue)
			*pcbValue = sz;
		if (ppbValue) {
			*ppbValue = LocalAlloc(0, sz);
			memcpy(*ppbValue, (void*)tbuf, sz);
		}
	}
	return S_OK;
}

HRESULT WINAPI SLGetWindowsInformationDWORD(
	PCWSTR                      pwszValueName,
	DWORD*                      pdwValue
)
{
	return SLGetWindowsInformation(pwszValueName, (void*)-1, (void*)-1, (PBYTE*)pdwValue);
}


static void *savedbuf;
static int savedlen;
typedef struct authinfo {
	DWORD len;
	DWORD type;
	DWORD hashlen;
	BYTE hashdata[0];
} authinfo;
static HRESULT WINAPI (*real_CryptGetHashParam)(HCRYPTHASH h, DWORD param, BYTE *out, DWORD *len, DWORD flags);
static HRESULT WINAPI my_CryptGetHashParam(HCRYPTHASH h, DWORD param, BYTE *out, DWORD *len, DWORD flags)
{
	int ret;
	if ((ret = real_CryptGetHashParam(h, param, out, len, flags))) {
		savedbuf = out;
		savedlen = *len;
	}
	return ret;
}

HRESULT WINAPI SLGetAuthenticationResult(
	HSLC 		hSLC,
	UINT*          	pcbValue,
	PBYTE*          ppbValue
)
{
	int len = savedlen + sizeof(authinfo);
	authinfo *ai = LocalAlloc(0, len);
	ai->len = len;
	ai->type = 2;
	ai->hashlen = savedlen;
	memcpy(ai->hashdata, savedbuf, savedlen);
	*pcbValue = len;
	*ppbValue = (void*)ai;
	return S_OK;
}

HRESULT WINAPI SLSetAuthenticationData(
	HSLC hSLC,
	UINT cbValue,
	const BYTE pbValue
)
{
	__declspec(dllimport) HRESULT WINAPI CryptGetHashParam(HCRYPTHASH, DWORD, PBYTE, DWORD*, DWORD);
	static int didsplice;
	if (didsplice)
		return S_OK;
	didsplice = 1;
	splice(CryptGetHashParam, my_CryptGetHashParam, (void*)&real_CryptGetHashParam);
	return S_OK;
}

BOOL APIENTRY WINAPI dll_main(HINSTANCE hModule, DWORD code, LPVOID ress)
{
	static int doneinit;
	if (code != DLL_PROCESS_ATTACH)
		return TRUE;
	if (doneinit)
		return TRUE;
	doneinit = 1;
	nconsumed = 1;

	return TRUE;
}
static HANDLE events[3];
static SERVICE_STATUS_HANDLE svch;
static SERVICE_STATUS status;

static VOID WINAPI handler(DWORD code)
{
	if (code == SERVICE_CONTROL_STOP) {
		status.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(svch, &status);
		SetEvent(events[2]);
	}
	return;
}

static int pol_unpack(UCHAR *blob, pol_ent **array)
{
	pol_hdr *h = (void*)blob;
	pol_ent *e = (void*)blob + sizeof(*h);
	void *endptr = ((void*)e) + h->data_sz;
	int n = 0;
	// Unusual.
	if (h->sz >= 65536)
		return -1;
	if (h->endpad != 4)
		return -2;
	if (h->data_sz+0x18 != h->sz)
		return -3;
	if (blob[h->sz-4] != 0x45)
		return -4;
	while (((void*)e) < endptr) {
		array[n++] = e;
		e->flags &= ~0x1000;
		e = ((void*)e) + e->sz;
		if (n == POL_MAX)
			return -1;
	}
	return n;
}

static int pol_pack(UCHAR *dst, pol_ent **array, int n)
{
	pol_hdr *h = (void*)dst;
	pol_ent *e = (void*)dst + sizeof(*h);
	int i = 0;
	memset(dst, 0, 65536);
	for (i = 0; i < n; i++) {
		int total = sizeof(*e) + array[i]->name_sz + array[i]->data_sz;
		if (!array[i]->name_sz) continue;
		memcpy((void*)e, (const void*)array[i], total);
		e->flags &= ~0x1000;
		total = (total + 4) & (~3);
		e->sz = total;
		e = ((void*)e) + total;
		h->data_sz += total;
	}
	h->sz = h->data_sz + 0x18;
	h->endpad = 4;
	h->pad1 = 1;
	dst[h->sz-4] = 0x45;
	return h->sz;
}

static const WCHAR *temp_path(WCHAR *buf)
{
	static WCHAR tbuf[PATH_MAX];
	if (!buf) buf = tbuf;
	GUID guid;
	CoCreateGuid(&guid);
	StringFromGUID2(&guid, buf + GetTempPath(PATH_MAX, buf), 64);
	return buf;
}


VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	__declspec(dllimport) NTSTATUS NTAPI RtlAdjustPrivilege(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);
	int i;

	// Bounds are not rigorously checked. If you put garbage into
	// kernel policy, ton of shit will hit the fan, not just important
	// svchost crashing.
	struct {
		BYTE polbuf[65536];
		BYTE polbuf2[65536];
		BYTE valbuf[65536];
		BYTE bigbuf[65536];
		WCHAR valn[PATH_MAX];
		pol_ent *ents[POL_MAX];
	} *b = NULL;
	HKEY keys[2] = {0};
	BOOLEAN old;

	if (GetSystemMetrics(SM_CLEANBOOT))
		goto bail;

       	b = malloc(sizeof(*b));
	if (!b)
		goto bail;

	// Check for WU in the hood. If present, just bail early, so as to not
	// complicate matters further.
#define PROBE "\\slc.dll"
	memcpy((char*)b->polbuf + GetSystemDirectoryA((char*)b->polbuf, PATH_MAX), PROBE, sizeof(PROBE));
	if (!(GetFileAttributesA((char*)b->polbuf) & FILE_ATTRIBUTE_REPARSE_POINT))
		goto bail;

	for (i = 0; i < 3; i++)
		if (!(events[i] = CreateEvent(NULL, TRUE, FALSE, NULL)))
			goto bail;

	if (!(NT_SUCCESS(RtlAdjustPrivilege(17, 1, 0, &old)) && NT_SUCCESS(RtlAdjustPrivilege(18, 1, 0, &old))))
		goto bail;

	status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	svch = RegisterServiceCtrlHandler(L"SLShim", handler);
	SetServiceStatus(svch, &status);

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\ProductOptions", 0, KEY_ALL_ACCESS, &keys[0]))
		goto bail;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KERNEL, 0, KEY_ALL_ACCESS, &keys[1]))
		goto bail;

	status.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(svch, &status);
	UINT evt = 1;
	RegNotifyChangeKeyValue(keys[0], FALSE,
		REG_NOTIFY_CHANGE_LAST_SET|REG_NOTIFY_CHANGE_NAME, events[0], TRUE);

	while (1) {
		DWORD valnsz = PATH_MAX;
		pol_ent *e;
		BYTE *p = b->bigbuf;
		DWORD ot;
		DWORD sz = 65536;
		if (RegQueryValueEx(keys[0], L"ProductPolicy", 0, &ot, b->polbuf, &sz))
			goto next;
		memset(b->ents, 0, sizeof(b->ents[0]) * POL_MAX);
		int nent = pol_unpack(b->polbuf, b->ents);
		if (nent < 0) goto next;

		// Now iterate values and modify kernel entries
		for (int i = 0; (valnsz = PATH_MAX) && !RegEnumValue(keys[1], i, b->valn, &valnsz, 0, &ot, b->valbuf, &sz); i++) {
			int j;
			int mirror = b->valn[valnsz-1] == L'_';
			if (mirror)
				valnsz--;
			for (j = 0; j < nent; j++) {
				if ((valnsz*2) == b->ents[j]->name_sz) {
					for (int k = 0; k < valnsz; k++) {
						if ((((WCHAR*)b->ents[j]->name)[k] != b->valn[k]) || (b->valn[k] == L'?') || (b->valn[k] == L'*'))
							goto skip;
					}
					break;
				}
skip:;
			}
			valnsz = valnsz*2;
			if ((ot == REG_DWORD) && b->valbuf[0] == DEADBEEF) {
				// nuke the entry
				if (j < nent) {
					e->flags |= 0x1000;
					b->ents[j]->flags |= 0x1000;
					b->ents[j]->name_sz = 0;
				}
				continue;
			}

			if (mirror) {
				if (j == nent)
					continue;
				// if the value is the same as of mirrored key, dont
				// update it (speed)
				if ((sz == b->ents[j]->data_sz) && (RtlCompareMemory(b->ents[j]->name + b->ents[j]->name_sz, b->valbuf, sz) == sz))
					b->ents[j]->flags |= 0x1000;
				continue;
			}

			e = (void*)p;
			p += sizeof(*e) + sz + valnsz;

			if (j == nent) {
				// create new entry
				e->flags = 0;
				if (nent >= POL_MAX)
					break;
				nent++;
			} else {
				// Replacing existing entry
				e->flags = b->ents[j]->flags;
			}
			// Mark this entry as visited, so that the second pass does not
			// do unnecesary write to registry.
			e->flags |= 0x1000;
			e->name_sz = valnsz;
			e->type = ot;
			e->data_sz = sz;
			e->pad0 = 0;
			memcpy(e->name, (const void*)b->valn, valnsz);
			memcpy(e->name + valnsz, b->valbuf, sz);
			b->ents[j] = e;
		}

		DWORD final = pol_pack(b->polbuf2, b->ents, nent);
		if (RegSaveKey(keys[0], temp_path(b->valn), NULL))
			goto next;
		HKEY hk2;
		const WCHAR *tp;
		if (RegCreateKeyEx(HKEY_CURRENT_USER, L"SLShim", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk2, NULL))
			goto outdel;
		if (RegRestoreKey(hk2, b->valn, REG_FORCE_RESTORE))
			goto outdel2;

		for (int i = 0; i < nent; i++) {
			static WCHAR tpk[256];
			UINT nl = b->ents[i]->name_sz/2;
			if (b->ents[i]->flags & 0x1000)
				continue;
			memcpy((void*)tpk, b->ents[i]->name, b->ents[i]->name_sz);
			tpk[nl] = L'_';
			tpk[nl+1] = 0;
			RegSetValueEx(keys[1], tpk, 0, b->ents[i]->type, b->ents[i]->name + b->ents[i]->name_sz, b->ents[i]->data_sz);
		}

		if (RegSetValueEx(hk2, L"ProductPolicy", 0, REG_BINARY, (void*)b->polbuf2, final))
			goto outdel;
		if (RegSaveKey(hk2, (tp = temp_path(NULL)), NULL))
			goto outdel2;
		RegRestoreKey(keys[0], tp, REG_FORCE_RESTORE); // Use IDA next time, Daz.
		DeleteFile(tp);
outdel2:
		RegCloseKey(hk2);
outdel:
		DeleteFile(b->valn);
next:;
		RegNotifyChangeKeyValue(keys[evt], FALSE,
			REG_NOTIFY_CHANGE_LAST_SET|REG_NOTIFY_CHANGE_NAME, events[evt], TRUE);
		evt = WaitForMultipleObjects(3, events, FALSE, INFINITE);
		if (evt >= 2) break;
	};
bail:;
	LocalFree(b);
	for (i = 0; i < 3; i++)
		CloseHandle(events[i]);
	for (i = 0; i < 2; i++)
		if (keys[i]) RegCloseKey(keys[i]);
	status.dwCurrentState = SERVICE_STOPPED;
	if (svch) SetServiceStatus(svch, &status);
}

void CALLBACK WINAPI SLShimSvcInit()
{
	HKEY k;
	BYTE vb[1024];
	DWORD ot, sz = sizeof(vb);
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", 0, KEY_ALL_ACCESS, &k))
		return;
#define SLSHIM L"SLShim"
	if (RegQueryValueExW(k, L"DcomLaunch", 0, &ot, vb, &sz))
		return;
	WCHAR *tp = (void*)(vb + sz - 2);
	if (RtlCompareMemory(&tp[-6], SLSHIM, sizeof(SLSHIM))==sizeof(SLSHIM))
		return;
	memcpy((void*)tp, (void*)SLSHIM, sizeof(SLSHIM));
	RegSetValueEx(k, L"DcomLaunch", 0, ot, vb, sz + sizeof(SLSHIM) - 2);
	RegCloseKey(k);
}


HRESULT WINAPI fill1(DWORD *g)
{
	*g = 0;
	return S_OK;
}
HRESULT WINAPI fill2(DWORD *g, void *b)
{
	*g = 0;
	return S_OK;
}
HRESULT WINAPI fill3(void *a, void *b, DWORD *g)
{
	*g = 0;
	return S_OK;
}

HRESULT WINAPI ok0()
{
	return S_OK;
}
HRESULT WINAPI ok1(void *a1)
{
	return S_OK;
}
HRESULT WINAPI ok2(void *a1, void *a2) { return S_OK; }
HRESULT WINAPI ok3(void *a1, void *a2, void *a3)
{
	return S_OK;
}
HRESULT WINAPI ok4(void *a1, void *a2, void *a3, void *a4)
{
	return S_OK;
}
HRESULT WINAPI ok5(void *a1, void *a2, void *a3, void *a4, void *a5)
{
	return S_OK;
}
HRESULT WINAPI ok6(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6)
{
	return S_OK;
}
HRESULT WINAPI ok7(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
	return S_OK;
}
HRESULT WINAPI ok8(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
	return S_OK;
}
HRESULT WINAPI unsupp1(void *a1)
{
	return SL_E_NOT_SUPPORTED;
}
HRESULT WINAPI unsupp2(void *a1,void*a2)
{
	return SL_E_NOT_SUPPORTED;
}
HRESULT WINAPI unsupp3(void *a1,void*a2,void*a3)
{
	return SL_E_NOT_SUPPORTED;
}
HRESULT WINAPI unsupp4(void *a1,void*a2,void*a3,void*a4) { return SL_E_NOT_SUPPORTED; }

HRESULT WINAPI unsupp5(void *a1,void*a2,void*a3,void*a4,void*a5)
{
	return SL_E_NOT_SUPPORTED;
}
HRESULT WINAPI unsupp6(void *a1,void*a2,void*a3,void*a4,void*a5,void*a6)
{
	return SL_E_NOT_SUPPORTED;
}
HRESULT WINAPI unsupp8(void *a1,void*a2,void*a3,void*a4,void*a5,void*a6,void*a7,void*a8)
{
	return SL_E_NOT_SUPPORTED;
}
HRESULT WINAPI unsupp9(void *a1,void*a2,void*a3,void*a4,void*a5,void*a6,void*a7,void*a8,void*a9)
{
	return SL_E_NOT_SUPPORTED;
}
HRESULT WINAPI unsupp10(void *a1,void*a2,void*a3,void*a4,void*a5,void*a6,void*a7,void*a8,void*a9,void*a10)
{
	return SL_E_NOT_SUPPORTED;
}




