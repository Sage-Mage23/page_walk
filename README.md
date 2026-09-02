# page_wallk
Anticheat pagewalking for memory backing

Concept is reversed from EAC and provided to me by Viper/Vralin, I improved the concept and publicly released it. 95% was written by me, other 5% and the rest of the read me was cursor fixing some of my mistakes but rewrote a good bit, plan on improving in the future when i have time. 

Looking for help or just want to chat? Dm me on discord: @deviceregion

Pagewalk is a read-only x64 kernel inspector: it translates virtual pages through physical page tables, parses PE metadata from copied headers, and walks loaded drivers page by page. In an anti-cheat kernel it answers “what is actually mapped for this image?” rather than “what does the module list claim?”

What it does
Copies go through MmCopyMemory. Virtual copies are a convenience; the walker and scanner rely on physical reads so a page-table entry is never treated as a kernel pointer. Success requires both a successful NTSTATUS and a full-length transfer.

The walker takes a DirectoryTableBase/CR3, masks PCID/cache bits and the physical-frame field (MAXPHYADDR when CPUID provides it), then walks PML5 (if CR4.LA57) → PML4 → PDPT → PD → PT. Each next-table address is entry & frame_mask, not the raw ULONG64. Leaves:

PTE → 4 KB
PDE.PS → 2 MB
PDPTE.PS → 1 GB
The result includes mapping level, raw entries, physical address of the leaf entry, mapped page base, VA→PA, page size/offset, and flags. Effective R/W and U/S are AND’d along the walk; NX is OR’d. Status is split into success, not-present, non-canonical VA, physical-read failure, unsupported paging, and reserved-bit leaves.

Loaded modules come from AuxKlibQueryModuleInformation. Identities are copied out, that buffer is freed, then each image is walked with no module-list lock held. Headers are copied through the walker before parse (DOS, e_lfanew, NT, optional header, section table, bounds-checked). Present 4 KB granules can be copied into a zeroed nonpaged snapshot; INIT/PAGE holes stay zero. Stats track 4K / 2M / 1G granules, not-present, unreadable, copy failures, and skips. Snapshot size is capped (16 MB per module, 64 MB total by default).

System DTB is read from KPROCESS.DirectoryTableBase at +0x28 on PsInitialSystemProcess, with __readcr3() as fallback. That offset is historically stable on x64 and still not a contract.

Why this shape matters for anti-cheat
A kernel integrity check that memcpys DllBase..SizeOfImage assumes a contiguous, resident mapping. That is often false: discarded INIT, paged-out PAGE sections, large pages, unload races, and KVA-shadow CR3 views. Walking physical tables and copying only present pages makes those cases visible instead of bugchecking or producing a silently wrong blob.

This still only sees guest page tables. VBS/HVCI/SLAT can disagree with what the guest PTE says. It does not attest the hypervisor.

Small improvements
Hash instead of (or in addition to) full snapshots. SHA-256 over present granules cuts nonpaged usage and is what most AC backends want anyway. Keep the zero-filled image only when you need a hex dump.
Walk by section, not the whole SizeOfImage. Integrity usually cares about executable sections. Skip discardable INIT after boot; treat PAGE holes as expected unless .text is missing.
Compare PTE policy to PE characteristics. Flag RWX, writable .text, or executable .data using the walker’s AND/OR flags vs IMAGE_SCN_*.
Decode software PTEs when Present=0. Prototype/transition/demand-zero entries are currently just “not present.” Windows MMPTE bits would separate “paged out” from “not a mapping.”
Don’t scan in DriverEntry. Queue a worker or expose an IOCTL so the anti-cheat service pulls results; boot-time walks of every driver stall load and pin pool.
Bind the DTB to the kernel map you intend. If the thread is in a shadowed user CR3, kernel driver VAs can look absent. Prefer System DTB and fail closed if the kernel PML4 slot is empty.
Replace the +0x28 DTB read with a versioned offset table or a documented-adjacent helper so a layout change doesn’t silently use the wrong CR3.
Retry or skip modules that vanish mid-walk. You already drop the list lock (correct); mark SizeOfImage vs present-byte ratio so a 90% hole looks like unload, not “clean.”
Optional on-disk compare. After a present-page snapshot, section-align against the file (or catalog hash) so you detect in-memory patches, not just missing pages.
Raise the anomaly cap or store a bitmap. 512 RVA records clip large holes; a 1-bit-per-granule map is smaller and complete.
