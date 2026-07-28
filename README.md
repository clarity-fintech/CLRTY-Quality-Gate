# CLRTY Quality Gate

CLRTY-1 · chain **1202** · quality / CI gate for clarity-fintech kits.

**Compiler policy:** only `bin/misc` checks `.mis` (Moniversive kernel). See `CLRTY_SUBSTRATE/boot/mis_kernel_active_only.json` in the monorepo.

```bash
# When .mis modules are present:
export CLRTY_ROOT=/path/to/CLRTY_PROJECT
export MISC="$CLRTY_ROOT/bin/misc"
make check
```
