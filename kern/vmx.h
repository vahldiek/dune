/*
 * vmx.h - header file for USM VMX driver.
 */

#include <linux/mmu_notifier.h>
#include <linux/types.h>
#include <asm/vmx.h>
#include <linux/kvm_types.h>

DECLARE_PER_CPU(struct vmx_vcpu *, local_vcpu);

struct vmcs {
    u32 revision_id;
    u32 abort;
    char data[0];
};

struct vmx_capability {
    u32 ept;
    u32 vpid;
    int has_load_efer:1;
};

extern struct vmx_capability vmx_capability;

#define NR_AUTOLOAD_MSRS 8

#define MAX_SECRET_MAPPINGS 16

enum vmx_reg {
    VCPU_REGS_RAX = 0,
    VCPU_REGS_RCX = 1,
    VCPU_REGS_RDX = 2,
    VCPU_REGS_RBX = 3,
    VCPU_REGS_RSP = 4,
    VCPU_REGS_RBP = 5,
    VCPU_REGS_RSI = 6,
    VCPU_REGS_RDI = 7,
#ifdef CONFIG_X86_64
    VCPU_REGS_R8 = 8,
    VCPU_REGS_R9 = 9,
    VCPU_REGS_R10 = 10,
    VCPU_REGS_R11 = 11,
    VCPU_REGS_R12 = 12,
    VCPU_REGS_R13 = 13,
    VCPU_REGS_R14 = 14,
    VCPU_REGS_R15 = 15,
#endif
    VCPU_REGS_RIP,
    NR_VCPU_REGS
};

struct secret_mapping {
    unsigned long gva; /* beginning of page */
    unsigned long len; /* bytes of this mapping (multiple of page size) */
    unsigned long ept_index;
};

struct vmx_vcpu {
    int cpu;
    int vpid;
    int launched;

    struct mmu_notifier mmu_notifier;
    spinlock_t ept_lock;
    bool ept_ad_enabled;

    u8  fail;
    u64 exit_reason;
    u64 host_rsp;
    u64 regs[NR_VCPU_REGS];
    u64 cr2;

    int shutdown;
    int ret_code;

    struct msr_autoload {
        unsigned nr;
        struct vmx_msr_entry guest[NR_AUTOLOAD_MSRS];
        struct vmx_msr_entry host[NR_AUTOLOAD_MSRS];
    } msr_autoload;

    struct vmcs *vmcs;
    void *syscall_tbl;

    unsigned num_epts;        /* num active, the lists are always 512 entries */
    unsigned long *eptp_list; /* list of EPT_POINTER-like values */
    void **ept_root_list;     /* list of va pointers to ept roots */
    unsigned long eptp;       /* current EPT_POINTER, read after every exit */
    struct secret_mapping secret_mappings[MAX_SECRET_MAPPINGS]; /* (fixed size!)
                                list of pages that are secret (only accessible
                                in 1 EPT). */
};

extern __init int vmx_init(void);
extern void vmx_exit(void);

extern int vmx_launch(struct dune_config *conf, int64_t *ret_code);

extern void *vmx_alloc_ept(void);
extern int vmx_create_ept(struct vmx_vcpu *vcpu);
extern void vmx_destroy_ept(struct vmx_vcpu *vcpu);
extern int vmx_init_eptp_list(struct vmx_vcpu *vcpu);
extern void vmx_free_eptp_list(struct vmx_vcpu *vcpu);

extern unsigned vmx_get_current_ept_index(struct vmx_vcpu *vcpu);

extern int
vmx_do_ept_fault(struct vmx_vcpu *vcpu, unsigned long gpa,
         unsigned long gva, int fault_flags);

extern void vmx_ept_sync_vcpu(struct vmx_vcpu *vcpu);
extern void vmx_ept_sync_individual_addr(struct vmx_vcpu *vcpu, gpa_t gpa);

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
        unsigned long value;

        asm volatile (ASM_VMX_VMREAD_RDX_RAX
                      : "=a"(value) : "d"(field) : "cc");
        return value;
}
