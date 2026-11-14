// #[global_allocator] over GetProcessHeap / HeapAlloc / HeapFree / HeapReAlloc.
// Four kernel32 names slot into the existing extern block in native.rs — no new
// DLL dependency, every legitimate Windows PE has these exact imports.

#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::{mem, ptr};

use crate::native::{GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc};

// HeapAlloc returns 16-byte aligned on x64. Anything larger takes the
// overallocate-and-stash-raw-ptr fallback.
const HEAP_ALIGN: usize = 2 * mem::size_of::<usize>();

pub struct ProcessHeap;

unsafe impl GlobalAlloc for ProcessHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = GetProcessHeap();
        if heap.is_null() { return ptr::null_mut(); }

        if layout.align() <= HEAP_ALIGN {
            HeapAlloc(heap, 0, layout.size()) as *mut u8
        } else {
            // Overalloc: [raw_ptr_slot][padding][aligned payload]
            let slop = layout.align() + mem::size_of::<*mut u8>();
            let raw  = HeapAlloc(heap, 0, layout.size() + slop) as *mut u8;
            if raw.is_null() { return ptr::null_mut(); }
            let base    = raw as usize + mem::size_of::<*mut u8>();
            let aligned = (base + layout.align() - 1) & !(layout.align() - 1);
            let out     = aligned as *mut u8;
            (out as *mut *mut u8).sub(1).write(raw);
            out
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        let heap = GetProcessHeap();
        if heap.is_null() { return; }
        let raw = if layout.align() <= HEAP_ALIGN {
            p
        } else {
            (p as *mut *mut u8).sub(1).read()
        };
        HeapFree(heap, 0, raw as *mut _);
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let heap = GetProcessHeap();
        if heap.is_null() { return ptr::null_mut(); }
        if layout.align() <= HEAP_ALIGN {
            HeapReAlloc(heap, 0, p as *mut _, new_size) as *mut u8
        } else {
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let fresh = self.alloc(new_layout);
            if !fresh.is_null() {
                ptr::copy_nonoverlapping(p, fresh, core::cmp::min(layout.size(), new_size));
                self.dealloc(p, layout);
            }
            fresh
        }
    }
}

#[global_allocator]
static ALLOCATOR: ProcessHeap = ProcessHeap;
