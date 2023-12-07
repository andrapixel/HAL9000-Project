#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread_internal.h"
#include "thread.h"
#include "filesystem.h"
#include "iomu.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION
#define MAX_PROCESSES 100
#define MAX_FILES 100

// Process handle structure
typedef struct _PROCESS_HANDLE {
    PPROCESS processPtr;
} PROCESS_HANDLE, * PPROCESS_HANDLE;

// Array that stores the process handles
PROCESS_HANDLE processHandleTable[MAX_PROCESSES];

// Function to retrieve the corresponding process of a given handle
PPROCESS RetrieveProcessFromHandle(UM_HANDLE ProcessHandle)
{
    if (ProcessHandle = 0 && ProcessHandle <= MAX_PROCESSES) {
        if (processHandleTable[ProcessHandle].processPtr != NULL) {
            return processHandleTable[ProcessHandle].processPtr;
        }
    }
    else {
        return NULL;
    }
}

// File handle structure
typedef struct _FILE_HANDLE {
    PFILE_OBJECT filePtr;
} FILE_HANDLE, * PFILE_HANDLE;

// Array that stores the process handles
FILE_HANDLE fileHandleTable[MAX_FILES];

// Function to retrieve the corresponding process of a given handle
PFILE_OBJECT RetrieveFileFromHandle(UM_HANDLE FileHandle)
{
    if (FileHandle > 0 && FileHandle <= MAX_FILES) {
        if (fileHandleTable[FileHandle].filePtr != NULL) {
            return fileHandleTable[FileHandle].filePtr;
        }
    }
    else {
        return NULL;
    }
}

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
        // STUDENT TODO: implement the rest of the syscalls
            // Process syscalls
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdProcessCreate:
            status = SyscallProcessCreate(
                (char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (char*)pSyscallParameters[2],
                (QWORD)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]
            );
            break;
        case SyscallIdProcessGetPid:
            status = SyscallProcessGetPid(
                (UM_HANDLE)pSyscallParameters[0],
                (PID*)pSyscallParameters[1]
            );
            break;
        case SyscallIdProcessWaitForTermination:
            status = SyscallProcessWaitForTermination(
                (UM_HANDLE)pSyscallParameters[0],
                (STATUS*)pSyscallParameters[1]
            );
            break;
        case SyscallIdProcessCloseHandle:
            status = SyscallProcessCloseHandle((UM_HANDLE)*pSyscallParameters);
            break;
            // File syscalls
        case SyscallIdFileCreate:
            status = SyscallFileCreate(
                (char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (BOOLEAN)pSyscallParameters[2],
                (BOOLEAN)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]
            );
            break;
        case SyscallIdFileClose:
            status = SyscallFileClose((UM_HANDLE)*pSyscallParameters);
            break;
        case SyscallIdFileRead:
            status = SyscallFileRead(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]
            );
            break;
        case SyscallIdFileWrite:
            status = SyscallFileWrite(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]
            );
            break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls
// Process syscalls
STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    PPROCESS currentProcess = GetCurrentProcess();

    // find handle associated with current process and clear the handle table
    UM_HANDLE currentProcessHandle = UM_INVALID_HANDLE_VALUE;
    for (int handleIndex = 1; handleIndex <= MAX_PROCESSES; ++handleIndex) {
        if (processHandleTable[handleIndex].processPtr == currentProcess) {
            currentProcessHandle = (UM_HANDLE)handleIndex;
            break;
        }
    }

    if (currentProcessHandle != UM_INVALID_HANDLE_VALUE) {
        processHandleTable[currentProcessHandle].processPtr = NULL;
    }

    currentProcess->TerminationStatus = ExitStatus;
    ProcessTerminate(currentProcess);

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
    char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
    char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE* ProcessHandle
)
{
    PPROCESS process = NULL;

    // validate input
    if (ProcessPath == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    if (!SUCCEEDED(MmuIsBufferValid((PVOID)ProcessPath, PathLength, PAGE_RIGHTS_READ, process)))
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (!SUCCEEDED(MmuIsBufferValid((PVOID)Arguments, ArgLength, PAGE_RIGHTS_READ, process)))
    {
        return STATUS_INVALID_PARAMETER3;
    }

    if (!SUCCEEDED(MmuIsBufferValid(ProcessHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_WRITE, process)))
    {
        return STATUS_INVALID_PARAMETER5;
    }

    // create process
    STATUS status = ProcessCreate(ProcessPath, Arguments, &process);

    // if not succeeded return error from ProcessCreate
    if (!SUCCEEDED(status)) {
        return status;
    }

    // assign handle
    int handleIndex = 1;
    while (handleIndex <= MAX_PROCESSES) {
        if (processHandleTable[handleIndex].processPtr == NULL) {
            break;
        }

        handleIndex++;
    }

    if (handleIndex > MAX_PROCESSES) {  // if handle table is full, terminate process
        ProcessTerminate(process);
        return STATUS_HEAP_INSUFFICIENT_RESOURCES;
    }

    processHandleTable[handleIndex].processPtr = process;
    *ProcessHandle = (UM_HANDLE)handleIndex;

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessGetPid(
    IN_OPT  UM_HANDLE               ProcessHandle,
    OUT     PID* ProcessId
)
{
    // get the PID for the currently executing process if handle is invalid
    if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
        *ProcessId = ProcessGetId(NULL);
        return STATUS_SUCCESS;
    }

    PPROCESS process = NULL;
    process = RetrieveProcessFromHandle(ProcessHandle);
    if (process == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    *ProcessId = ProcessGetId(process);

    if (!SUCCEEDED(MmuIsBufferValid(ProcessId, sizeof(PID), PAGE_RIGHTS_WRITE, process))) {
        return STATUS_INVALID_PARAMETER2;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessWaitForTermination(
    IN      UM_HANDLE               ProcessHandle,
    OUT     STATUS* TerminationStatus
)
{
    if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_INVALID_PARAMETER1;
    }

    PPROCESS process = NULL;
    process = RetrieveProcessFromHandle(ProcessHandle);
    if (process == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    ProcessWaitForTermination(process, TerminationStatus);

    if (!SUCCEEDED(MmuIsBufferValid(TerminationStatus, sizeof(STATUS), PAGE_RIGHTS_WRITE, process)))
    {
        return STATUS_INVALID_PARAMETER2;
    }

    return *TerminationStatus;
}

STATUS
SyscallProcessCloseHandle(
    IN      UM_HANDLE               ProcessHandle
)
{
    if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_INVALID_PARAMETER1;
    }

    PPROCESS process = NULL;
    process = RetrieveProcessFromHandle(ProcessHandle);
    if (process == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    ProcessCloseHandle(process);
    // clear handle table entry for the closed handle
    processHandleTable[ProcessHandle].processPtr = NULL;

    return STATUS_SUCCESS;
}

// File syscalls
STATUS
SyscallFileCreate(
    IN_READS_Z(PathLength)
    char* Path,
    IN          QWORD                   PathLength,
    IN          BOOLEAN                 Directory,
    IN          BOOLEAN                 Create,
    OUT         UM_HANDLE* FileHandle
)
{
    PFILE_OBJECT file = NULL;

    if (Path == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    PPROCESS process = GetCurrentProcess();
    if (process == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    if (!SUCCEEDED(MmuIsBufferValid((PVOID)Path, PathLength, PAGE_RIGHTS_READ, process))) {
        return STATUS_INVALID_PARAMETER1;
    }
    if (!SUCCEEDED(MmuIsBufferValid(FileHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_WRITE, process))) {
        return STATUS_INVALID_PARAMETER5;
    }

    // construct full path
    char fullPath[MAX_PATH];
    if (Path[1] == ":" && Path[2] == '\\') {
        strcpy(fullPath, Path);
    }
    else {
        char* systemDrive = IomuGetSystemPartitionPath();
        sprintf(fullPath, "%s%s", systemDrive, Path);
    }

    // create file
    STATUS status = IoCreateFile(&file, fullPath, Directory, Create, FALSE);

    if (!SUCCEEDED(status)) {
        return status;
    }

    // assign handle
    int handleIndex = 1;
    while (handleIndex <= MAX_FILES) {
        if (fileHandleTable[handleIndex].filePtr == NULL) {
            break;
        }

        handleIndex++;
    }

    if (handleIndex > MAX_FILES) {
        return STATUS_HEAP_INSUFFICIENT_RESOURCES;
    }

    fileHandleTable[handleIndex].filePtr = file;
    *FileHandle = (UM_HANDLE)handleIndex;

    return STATUS_SUCCESS;
}

STATUS
SyscallFileClose(
    IN          UM_HANDLE               FileHandle
)
{
    if (FileHandle == UM_INVALID_HANDLE_VALUE || FileHandle > MAX_FILES) {
        return STATUS_INVALID_PARAMETER1;
    }

    PFILE_OBJECT file = NULL;
    file = RetrieveFileFromHandle(FileHandle);
    if (file == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    STATUS status = IoCloseFile(file);

    if (!SUCCEEDED(status)) {
        return STATUS_UNSUCCESSFUL;
    }

    // clear handle table entry for the closed file
    fileHandleTable[FileHandle].filePtr = NULL;
    return STATUS_SUCCESS;
}

STATUS
SyscallFileRead(
    IN  UM_HANDLE                   FileHandle,
    OUT_WRITES_BYTES(BytesToRead)
    PVOID                       Buffer,
    IN  QWORD                       BytesToRead,
    OUT QWORD* BytesRead
)
{
    if (FileHandle == UM_INVALID_HANDLE_VALUE || FileHandle > MAX_FILES) {
        return STATUS_INVALID_PARAMETER1;
    }

    PPROCESS process = GetCurrentProcess();
    if (process == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    if (!SUCCEEDED(MmuIsBufferValid(Buffer, sizeof(PVOID), PAGE_RIGHTS_READ, process))) {
        return STATUS_INVALID_PARAMETER2;
    }

    PFILE_OBJECT file = NULL;
    file = RetrieveFileFromHandle(FileHandle);
    if (file == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    STATUS status = IoReadFile(file, BytesToRead, NULL, Buffer, BytesRead);
    if (!SUCCEEDED(status)) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                       Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    if (FileHandle == UM_INVALID_HANDLE_VALUE || FileHandle > MAX_FILES) {
        return STATUS_INVALID_PARAMETER1;
    }

    if (BytesWritten == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    PFILE_OBJECT file = NULL;
    file = RetrieveFileFromHandle(FileHandle);
    if (file == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        *BytesWritten = BytesToWrite;
        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
        return STATUS_SUCCESS;
    }

    STATUS status = IoWriteFile(file, BytesToWrite, NULL, Buffer, BytesWritten);

    if (!SUCCEEDED(status)) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}