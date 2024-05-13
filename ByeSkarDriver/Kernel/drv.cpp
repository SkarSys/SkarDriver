#include <ntifs.h>
#include <windef.h> 

// Eugh wtf!!! This code dosnt look AT ALL as clean as the usermode!? why?? Well, now its your turn to learn, being "UD" in a video game will not bring anything to your life.
// I decided to make this project so people can learn a thing or two. Dont worry i will add comments everywhere to help u make this better and explain some stuff! - Skar

// First lemme start with a little tip: when naming vars, people do it differnet ways and i used to name them somewhat randomly or in cammel case, or even seperate them with 
// underscores... but, i find the best way is the use cammel case and the first letter of the type in the var or function (for function it would be the return type)
// example: bool bIsBlack, void vGetRace, int iNumberOfHoes, etc.. you get the point. you can also do the same for structs, classes, namespaces but yh its just prefernces tbh
// another organization tip: i like to use Filters (fake folders that r onlt visible in vs) to organize ALL my headers and code

UNICODE_STRING name, link; // defining vars, consider renaming them in the way mentioned amouve and maybe make a new header for for them like i did in usermode (settings.h)

typedef struct _SYSTEM_BIGPOOL_ENTRY { // in these we r defining (3) sturcts and we will use the data in them later. (tip: move to header)
	PVOID VirtualAddress;				// in kmd's u offen need to deffine extra stuff like functions that u can import from windows itself
	ULONG_PTR NonPaged : 1;				// some of these are UNDOCUMENTED! and allot r usfull shit, u can read documentation or even reverse 
	ULONG_PTR SizeInBytes;				// or look at imports/exports of diff apps to see what they call. keep in mind most shit in usermode 
	UCHAR Tag[4];						// actually calls a kernel mode equivilent function, and thats a syscall.
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBigPoolInformation = 0x42,
} SYSTEM_INFORMATION_CLASS;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // like in the um, we need to define our ctl codes, make sure these match the usermode ones
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x72, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // there r some rules in terms of size and wether ur driver is in signed memory or manually mapped
#define code_get_guarded_region CTL_CODE(FILE_DEVICE_UNKNOWN, 0x73, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // but i will let u do that research.
#define code_security 0x85b3e12 // this is not a ctl code its just a lil "security" fetures meaning when u communicate with this driver that code is one of the needed arguments, it will make it a tiny bit
// harder for anyone to try and use ur driver and can help in other ways but tbh its not that imporant, if somone wants to use the driver they would need to reverse ur ctl codes, device name and well obviously 
// so maybe name it somthing less sus. i nammed it cKey in um so u can do the same here.
// oh and the tip: move to header and rename it, u should name it i defined them in the um so u dont get confused with 10 dif vars for the same shit

#define win_1803 17134 // all of these will help us check the winver (windows version)
#define win_1809 17763 // to check urs -> win+r and type winver 
#define win_1903 18362 // hope u bsod btw ;)
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19569
#define win_21H1 20180

#define PAGE_OFFSET_SIZE 12 // if intrested -> https://github.com/waryas/UMPMLib/blob/master/MemoryOperationSample/PMemHelper.h / https://www.unknowncheats.me/forum/3085599-post1.html 
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull; // btw u will need to understand hex, in hex F is always the highest char and is like 9 in dec (when u see 0xFFFFFFF... it usually means its trying to define somthings max size or a very big hex value)
// once u learn hex u will be able to code shit like this:
// 736b6172206973207468652062657374206475646520696e20636f6d6d20616e64206c6f7665732075 (NO CHEATING)

typedef struct _rw { // i talekd about this befour but structs r basically like a way to group vars together with diff members that can have diff types
	INT32 security; // u can access them like this -> structname.varname
	INT32 process_id; // there r other ways but yh its usfull for organizing stuff 
	ULONGLONG address; // for these 3 structs u should make a header with them and rename them to they match the ones in usermode
	ULONGLONG buffer; // another thing to do is change them completly. u can change the ammout of members, there types, and play around with them
	ULONGLONG size; // i recomend u change them and maybe add more fetures. be creative
	BOOLEAN write;
} rw, * prw;

typedef struct _ba {
	INT32 security;
	INT32 process_id;
	ULONGLONG* address;
} ba, * pba;

typedef struct _ga {
	INT32 security;
	ULONGLONG* address;
} ga, * pga;

NTSTATUS read(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) { // the return type is NTSTATUS (32bit) and that is usally used in functions in drivers, as the name suggests it returns a status but it could be other shit too
	MM_COPY_ADDRESS to_read = { 0 };													// im not sure if i should keep resaying the tip so from now on u get the point: raname var -> organize as u like (header for example)			
	to_read.PhysicalAddress.QuadPart = (LONGLONG)target_address;							// (dont forget to include the header too)
	return MmCopyMemory(buffer, to_read, size, MM_COPY_MEMORY_PHYSICAL, bytes_read);
}

NTSTATUS write(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read)
{
	if (!target_address)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = LONGLONG(target_address);

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, buffer, size);

	*bytes_read = size;
	MmUnmapIoSpace(pmapped_mem, size);
	return STATUS_SUCCESS;
}

INT32 get_winver() { // as explnained befour this is to get ur winver
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);
	switch (ver.dwBuildNumber)
	{
	case win_1803:
		return 0x0278;
		break;
	case win_1809:
		return 0x0278;
		break;
	case win_1903:
		return 0x0280;
		break;
	case win_1909:
		return 0x0280;
		break;
	case win_2004:
		return 0x0388;
		break;
	case win_20H2:
		return 0x0388;
		break;
	case win_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

UINT64 get_process_cr3(const PEPROCESS pProcess) { // learn some assembly, cr3 is a register and used for virtual tables. btw u should really learn about memory and more abotu winapi, asm, etc!
	PUCHAR process = (PUCHAR)pProcess;				// these tables hold addresses (like ur address but in memory) and these niggas usually point to other addys (as if there is a signe on ur home saying "go to '123 nigga street that way ->'
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
	if (process_dirbase == 0) {
		INT32 UserDirOffset = get_winver();
												// will need to do some more stuff here, uc is a good resource and github. (tip: find an alternative then using KeAttachProcess if trying to bypess eac or smt)
		ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
		return process_userdirbase;
	}

	return process_dirbase;
}

UINT64 translate_linear(UINT64 directoryTableBase, UINT64 virtualAddress) { // dont wanna explain all this cus its not 2am on a school night and i low key got a test tmr idk what im doing
	directoryTableBase &= ~0xf;												// but... this func returns a physical address and takes in the addy of the dtb (DirectoryTableBase) and a virtual addy 
																			// it retuns a physical address
	UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);		// physmem is not as documents as vitual mem. i trust u will do ur own resarch on this tho
	UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
	UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
	UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
	UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	UINT64 pdpe = 0;
	read(PVOID(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	UINT64 pde = 0;
	read(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	UINT64 pteAddr = 0;
	read(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	read(PVOID((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

ULONG64 find_min(INT32 g, SIZE_T f) {
	INT32 h = (INT32)f;
	ULONG64 result = 0;

	result = (((g) < (h)) ? (g) : (h));

	return result;
}

NTSTATUS frw(prw x) { // it basically recives the order and then does what it has to do so in this case reading or write mem
	if (x->security != code_security)
		return STATUS_UNSUCCESSFUL;

	if (!x->process_id)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
	if (!process)
		return STATUS_UNSUCCESSFUL;

	ULONGLONG process_base = get_process_cr3(process);
	ObDereferenceObject(process);

	SIZE_T this_offset = NULL;
	SIZE_T total_size = x->size;

	INT64 physical_address = translate_linear(process_base, (ULONG64)x->address + this_offset);
	if (!physical_address)
		return STATUS_UNSUCCESSFUL;

	ULONG64 final_size = find_min(PAGE_SIZE - (physical_address & 0xFFF), total_size);
	SIZE_T bytes_trough = NULL;

	if (x->write) {
		write(PVOID(physical_address), (PVOID)((ULONG64)x->buffer + this_offset), final_size, &bytes_trough);
	}
	else {
		read(PVOID(physical_address), (PVOID)((ULONG64)x->buffer + this_offset), final_size, &bytes_trough);
	}

	return STATUS_SUCCESS;
}

NTSTATUS fba(pba x) { // same thig here 
	if (x->security != code_security)
		return STATUS_UNSUCCESSFUL;

	if (!x->process_id)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
	if (!process)
		return STATUS_UNSUCCESSFUL;

	ULONGLONG image_base = (ULONGLONG)PsGetProcessSectionBaseAddress(process);
	if (!image_base)
		return STATUS_UNSUCCESSFUL;

	RtlCopyMemory(x->address, &image_base, sizeof(image_base));
	ObDereferenceObject(process);

	return STATUS_SUCCESS;
}

NTSTATUS fget_guarded_region(pga x) { // and here
	if (x->security != code_security)
		return STATUS_UNSUCCESSFUL;

	ULONG infoLen = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemBigPoolInformation, &infoLen, 0, &infoLen);
	PSYSTEM_BIGPOOL_INFORMATION pPoolInfo = 0;

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (pPoolInfo)
			ExFreePool(pPoolInfo);

		pPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, infoLen);
		status = ZwQuerySystemInformation(SystemBigPoolInformation, pPoolInfo, infoLen, &infoLen);
	}

	if (pPoolInfo)
	{
		for (unsigned int i = 0; i < pPoolInfo->Count; i++)
		{
			SYSTEM_BIGPOOL_ENTRY* Entry = &pPoolInfo->AllocatedInfo[i];
			PVOID VirtualAddress;
			VirtualAddress = (PVOID)((uintptr_t)Entry->VirtualAddress & ~1ull);
			SIZE_T SizeInBytes = Entry->SizeInBytes;
			BOOLEAN NonPaged = Entry->NonPaged;

			if (Entry->NonPaged && Entry->SizeInBytes == 0x200000) {
				UCHAR expectedTag[] = "TnoC";  // Tag should be a string, not a ulong
				if (memcmp(Entry->Tag, expectedTag, sizeof(expectedTag)) == 0) {
					RtlCopyMemory((void*)x->address, &Entry->VirtualAddress, sizeof(Entry->VirtualAddress));
					return STATUS_SUCCESS;
				}
			}

		}

		ExFreePool(pPoolInfo);
	}

	return STATUS_SUCCESS;
}

NTSTATUS io_controller(PDEVICE_OBJECT device_obj, PIRP irp) { // this will handle the requsts and depending on what they r pass them to diff functions / return them 
	UNREFERENCED_PARAMETER(device_obj);

	NTSTATUS status = { };
	ULONG bytes = { };
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

	if (code == code_rw) {
		if (size == sizeof(_rw)) {
			prw req = (prw)(irp->AssociatedIrp.SystemBuffer);

			status = frw(req);
			bytes = sizeof(_rw);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_ba) {
		if (size == sizeof(_ba)) {
			pba req = (pba)(irp->AssociatedIrp.SystemBuffer);

			status = fba(req);
			bytes = sizeof(_ba);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_get_guarded_region) {
		if (size == sizeof(_ga)) {
			pga req = (pga)(irp->AssociatedIrp.SystemBuffer);

			status = fget_guarded_region(req);
			bytes = sizeof(_ga);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS unsupported_dispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return irp->IoStatus.Status;
}

NTSTATUS dispatch_handler(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	switch (stack->MajorFunction) {
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_CLOSE:
		break;
	default:
		break;
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

void unload_drv(PDRIVER_OBJECT drv_obj) { // this unloads the driver and deletes the symbolic link
	NTSTATUS status = { };

	status = IoDeleteSymbolicLink(&link);

	if (!NT_SUCCESS(status))
		return;

	IoDeleteDevice(drv_obj->DeviceObject);
}

NTSTATUS initialize_driver(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path) { //  setup for the driver 
	UNREFERENCED_PARAMETER(path);

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT device_obj = NULL;

	UNICODE_STRING name, link;
	RtlInitUnicodeString(&name, L"\\Device\\IoControlDevice"); //  make sure to change this and make it the same in um
	RtlInitUnicodeString(&link, L"\\DosDevices\\IoControl"); // same here, oh and u should use xor to encrpyts strings

	status = IoCreateDevice(drv_obj, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = IoCreateSymbolicLink(&link, &name);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(device_obj);
		return status;
	}

	// irp dispathc funncs
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		drv_obj->MajorFunction[i] = &unsupported_dispatch;
	}

	drv_obj->MajorFunction[IRP_MJ_CREATE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_CLOSE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &io_controller;
	drv_obj->DriverUnload = &unload_drv;

	device_obj->Flags |= DO_BUFFERED_IO;
	device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) { // this is the equivlent of main(), here its simple: we just call IoCreateDriver (that returns an NTSTATUS)
	UNREFERENCED_PARAMETER(DriverObject); // dont delete me orima bsod the shit outta u
	UNREFERENCED_PARAMETER(RegistryPath); // same pls dont del me or i will touch u

	return IoCreateDriver(NULL, &initialize_driver);
}


// to finish this off:
// 1. if u have questions, erorrs u can dm me and my gh is github.com/skarsys but pls try to fix the error urself befour asking, allot of times its in properties and disable treate warning as error or simple configuration. u can always lookup and error (tip: stackoverlflow is very helpfull for shitty errors and questions)
// 2. this (ioctl dispatch) is not the only "type" of driver, when i say type i mean the communication method. here r some others -> shared memory, .data ptr, socket, callback, namepipe, etc... what should u use? YOUR OWN! (and look at this for more info on diff ones https://github.com/adspro15/km-um-communication)
// 3. make sure to downlaod the wdk (win. driver kit) or none of this will work. and disable sprectr mitigation in proprties so u dont need to waste space on ur pc for those fat ahh libs

// i hope u liked this, i didnt wanna spoon feed so that way u can get smt out of it. i dont think i will post any more game hacking related sources as im more into malware developement (ethical only ofc ;))
// my discord is skarsys but dont be surpriesed if im termed
// make sure to have fun and remember that the point is not to be "ud" but is to learn how to code and grow ur knolege, if u have diffent objectives like money u should prolly use ur limited time to do smt u enjoy in life.
// sincerely, 
// - Skar.
// ps: if there r allot of typos and not everything is well writed im sorry but im tiered asf
 
// https://github.com/skarsys 