# suritop-web-overlay-beta

Beta Gentoo overlay for the **suritop-web** security monitoring system.

## Installation via eselect repository

The recommended way to install this overlay on Gentoo Linux:

```bash
# Add the overlay
eselect repository add suritop-web git https://github.com/PEAKT0P/suritop-web-overlay-beta.git

# Sync the overlay
emerge --sync suritop-web

# Install the package
emerge --ask net-analyzer/suritop-web
```

## Manual installation from tarball

If you prefer to install from the provided `suritop-web-overlay-beta.tar.gz`:

```bash
# Extract to /var/db/repos/
tar -xzf suritop-web-overlay-beta.tar.gz -C /var/db/repos/

# Verify the overlay is recognized
eselect repository list | grep suritop-web

# Sync and install
emerge --sync suritop-web
emerge --ask net-analyzer/suritop-web
```

## Removal

```bash
eselect repository disable suritop-web
# or remove manually:
rm -rf /var/db/repos/suritop-web-overlay-beta
```

## Links

- GitHub: https://github.com/PEAKT0P/suritop-web-overlay-beta
