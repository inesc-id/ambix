M(int, walk_page_range, (
            struct mm_struct *mm,
            unsigned long start,
            unsigned long end,
            const struct mm_walk_ops *ops,
            void *private));
