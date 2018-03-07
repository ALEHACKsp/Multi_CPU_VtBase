#pragma once

GUEST_REGS g_GuestRegs[8];

ULONG GetCurrentGuestReg()
{
	ULONG ProcessorIndex;

	ProcessorIndex = KeGetCurrentProcessorNumber();

	return (ULONG)&g_GuestRegs[ProcessorIndex];
}

void HandleCPUID()
{
	CPUID_VALUE Cpuid_Value;
	ULONG CurrentIndex;

	CurrentIndex = KeGetCurrentProcessorNumber();

	if (g_GuestRegs[CurrentIndex].eax == 'Mini')
	{
		g_GuestRegs[CurrentIndex].ebx = 0x88888888;
		g_GuestRegs[CurrentIndex].ecx = 0x11111111;
		g_GuestRegs[CurrentIndex].edx = 0x12345678;
	}
	else
	{
		Cpuid_Value = Asm_GetCpuid(g_GuestRegs[CurrentIndex].eax);
		g_GuestRegs[CurrentIndex].ebx = Cpuid_Value.u_Ebx;
		g_GuestRegs[CurrentIndex].ecx = Cpuid_Value.u_Ecx;
		g_GuestRegs[CurrentIndex].edx = Cpuid_Value.u_Edx;
	}
}

void HandleInvd()
{
	Asm_Invd();
}

void HandleVmCall()
{
	ULONG JmpEIP;

	ULONG CurrentIndex;

	CurrentIndex = KeGetCurrentProcessorNumber();

	if (g_GuestRegs[CurrentIndex].eax == 'SVT')
	{
		JmpEIP = g_GuestRegs[CurrentIndex].eip + Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);
		Vmx_VmxOff();

		Asm_AfterVMXOff(g_GuestRegs[CurrentIndex].esp, JmpEIP);
	}
}

void HandleMsrRead()
{
	ULONG CurrentIndex;

	CurrentIndex = KeGetCurrentProcessorNumber();

	switch (g_GuestRegs[CurrentIndex].ecx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		g_GuestRegs[CurrentIndex].eax = Vmx_VmRead(GUEST_SYSENTER_CS);
		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		g_GuestRegs[CurrentIndex].eax = Vmx_VmRead(GUEST_SYSENTER_ESP);
		break;
	}
	case MSR_IA32_SYSENTER_EIP:	// KiFastCallEntry
	{
		g_GuestRegs[CurrentIndex].eax = Vmx_VmRead(GUEST_SYSENTER_EIP);
		break;
	}
	default:
		g_GuestRegs[CurrentIndex].eax = (ULONG)Asm_Rdmsr(g_GuestRegs[CurrentIndex].ecx);
	}

}

void HandleMsrWrite()
{
	ULONG CurrentIndex;

	CurrentIndex = KeGetCurrentProcessorNumber();

	switch (g_GuestRegs[CurrentIndex].ecx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		Vmx_VmWrite(GUEST_SYSENTER_CS, g_GuestRegs[CurrentIndex].eax);
		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		Vmx_VmWrite(GUEST_SYSENTER_ESP, g_GuestRegs[CurrentIndex].eax);
		break;
	}
	case MSR_IA32_SYSENTER_EIP:	// KiFastCallEntry
	{
		Vmx_VmWrite(GUEST_SYSENTER_EIP, g_GuestRegs[CurrentIndex].eax);
		break;
	}
	default:
		Asm_WrMsr(g_GuestRegs[CurrentIndex].ecx, g_GuestRegs[CurrentIndex].eax, g_GuestRegs[CurrentIndex].edx);
	}
}

void HandleCrAccess()
{
	ULONG		movcrControlRegister;
	ULONG		movcrAccessType;
	ULONG		movcrOperandType;
	ULONG		movcrGeneralPurposeRegister;
	ULONG		movcrLMSWSourceData;
	ULONG		ExitQualification;

	ULONG		CurrentIndex;

	CurrentIndex = KeGetCurrentProcessorNumber();

	ExitQualification = Vmx_VmRead(EXIT_QUALIFICATION);
	movcrControlRegister = (ExitQualification & 0x0000000F);
	movcrAccessType = ((ExitQualification & 0x00000030) >> 4);
	movcrOperandType = ((ExitQualification & 0x00000040) >> 6);
	movcrGeneralPurposeRegister = ((ExitQualification & 0x00000F00) >> 8);

	//	Control Register Access (CR3 <-- reg32)
	//
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[CurrentIndex].eax);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[CurrentIndex].ecx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[CurrentIndex].edx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[CurrentIndex].ebx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[CurrentIndex].esp);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[CurrentIndex].ebp);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[CurrentIndex].esi);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[CurrentIndex].edi);
	}
	//	Control Register Access (reg32 <-- CR3)
	//
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0)
	{
		g_GuestRegs[CurrentIndex].eax = g_GuestRegs[CurrentIndex].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1)
	{
		g_GuestRegs[CurrentIndex].ecx = g_GuestRegs[CurrentIndex].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2)
	{
		g_GuestRegs[CurrentIndex].edx = g_GuestRegs[CurrentIndex].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3)
	{
		g_GuestRegs[CurrentIndex].ebx = g_GuestRegs[CurrentIndex].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4)
	{
		g_GuestRegs[CurrentIndex].esp = g_GuestRegs[CurrentIndex].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5)
	{
		g_GuestRegs[CurrentIndex].ebp = g_GuestRegs[CurrentIndex].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6)
	{
		g_GuestRegs[CurrentIndex].esi = g_GuestRegs[CurrentIndex].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7)
	{
		g_GuestRegs[CurrentIndex].edi = g_GuestRegs[CurrentIndex].cr3;
	}
}

void ExitHandle()
{
	ULONG ExitReason;
	ULONG ExitInstructionLength;
	ULONG GuestResumeEIP;

	ULONG CurrentIndex;

	CurrentIndex = KeGetCurrentProcessorNumber();

	ExitReason = Vmx_VmRead(VM_EXIT_REASON);
	ExitInstructionLength = Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);

	g_GuestRegs[CurrentIndex].esp = Vmx_VmRead(GUEST_RSP);
	g_GuestRegs[CurrentIndex].eip = Vmx_VmRead(GUEST_RIP);
	g_GuestRegs[CurrentIndex].cr3 = Vmx_VmRead(GUEST_CR3);

	switch (ExitReason)
	{
	case EXIT_REASON_CPUID:
	{
		HandleCPUID();
		break;
	}
	case EXIT_REASON_INVD:
	{
		HandleInvd();
		break;
	}
	case EXIT_REASON_VMCALL:
	{
		HandleVmCall();
		break;
	}
	case EXIT_REASON_MSR_READ:
	{
		HandleMsrRead();
		break;
	}
	case EXIT_REASON_MSR_WRITE:
	{
		HandleMsrWrite();
		break;
	}
	case EXIT_REASON_CR_ACCESS:
	{
		HandleCrAccess();
		break;
	}
	default:
		break;
	}
	GuestResumeEIP = g_GuestRegs[CurrentIndex].eip + ExitInstructionLength;
	Vmx_VmWrite(GUEST_RIP, GuestResumeEIP);
	Vmx_VmWrite(GUEST_RSP, g_GuestRegs[CurrentIndex].esp);
}

//按照我的理解，因为最后调用的是vmresume而不是ret，所以这里必须用naked函数，不然堆栈会崩掉。
//然后再调用一个C语言函数来写逻辑
void __declspec(naked) Vmx_VMMEntryPoint()
{
	__asm
	{
		cli

		mov[esp - 96h], eax;
		mov[esp - 100h], ebx;								//保存一下eax，ebx到堆栈中

		push ebx;
		push ecx;
		push edx;
		push esp;
		push ebp;
		push esi;
		push edi;

		call GetCurrentGuestReg;
		
		pop edi;
		pop esi;
		pop ebp;
		pop esp;
		pop edx;
		pop ecx;
		pop ebx;

		mov[eax + 4h], ecx;
		mov[eax + 8h], edx;
		mov[eax + 0Ch], ebx;
		mov[eax + 10h], esp;
		mov[eax + 14h], ebp;
		mov[eax + 18h], esi;
		mov[eax + 1Ch], edi;
		mov ebx, [esp - 96h];
		mov[eax], ebx;
		mov eax, [esp - 96h];
		mov ebx, [esp - 100h];

		call ExitHandle;

		call GetCurrentGuestReg;

		mov ecx, [eax + 4h];
		mov edx, [eax + 8h];
		mov ebx, [eax + 0Ch];
		mov esp, [eax + 10h];
		mov ebp, [eax + 14h];
		mov esi, [eax + 18h];
		mov edi, [eax + 1Ch];
		mov eax, [eax];
		sti;

		_emit 0x0F;
		_emit 0x01;
		_emit 0xC3;			//vmresume
	}
}