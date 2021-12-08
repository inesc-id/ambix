M(int, walk_page_range, (
            struct mm_struct *mm,
            unsigned long start,
            unsigned long end,
            const struct mm_walk_ops *ops,
            void *private));
M(void, si_meminfo_node, (struct sysinfo *val, int nid));
M(int, migrate_pages, (
            struct list_head *l,
            new_page_t new,
            free_page_t free,
            unsigned long private,
            enum migrate_mode mode,
            int reason));
M(void, putback_movable_pages, (struct list_head *l));
M(struct page *, follow_page, (
            struct vm_area_struct *vma,
            unsigned long address,
            unsigned int foll_flags));
M(int, isolate_lru_page, (struct page *page));
M(bool, isolate_huge_page, (struct page *page, struct list_head *list));
M(bool, vma_migratable, (struct vm_area_struct *vma));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,5)
#else
    M(void, lru_add_drain_all, (void));
#endif
