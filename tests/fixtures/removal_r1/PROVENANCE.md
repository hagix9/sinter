# Stage R1 preview fixtures — provenance

Preview `.out`/`.err` files are byte copies of Stage R0 real-Linux captures.
`dnf4_absent.*` is reconstructed from the R0 transcript because the raw no-op
files were not copied before the Rocky VM stopped; the content is exactly the
R0 output shown in `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/dnf4-absent-preview.txt`.

The three `inventory_*` files are the full R0 baseline inventories. The R1
fingerprint hash is over a canonical `name<TAB>arch<TAB>version<TAB>installed`
listing, so it is intentionally not the raw-file SHA-256 shown below.

| fixture | SHA-256 | R0 source |
|---|---|---|
| `apt_absent.err` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/apt-absent.err` |
| `apt_absent.out` | `f8166e5991743361a4965cd42202b1988d2a60144d1a8851d301edeb7a7871c7` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/apt-absent.out` |
| `apt_auto_remove.out` | `69dd6f5783460136e51d026139828e956b1cb6eed74003399594377a09f40f78` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/apt-p3.out` |
| `apt_reverse.err` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/apt-p1.err` |
| `apt_reverse.out` | `6c445b5752fb2f1ea8e4f9f2cd6b470e13a026ffeecc46f2000d75474df6dd91` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/apt-p1.out` |
| `apt_root_reverse.out` | `e7bfafaf508013f05cdf4bc08226118d40141318a4ad4c52986f09b466e81b12` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/apt-root-p1.out` |
| `apt_single.err` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/apt-p2.err` |
| `apt_single.out` | `e3d57ea5fa7acb554c959524c8ca4cda533b3725e7f87bbb99c7ee2e208b966c` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/apt-p2.out` |
| `dnf4_absent.err` | `d33299541bfc115f2057aa27eeb61fe4e0cfee539166813a8f01392f78f86c22` | `reconstructed from R0 evidence/rocky/dnf4-absent-preview.txt` |
| `dnf4_absent.out` | `cb4cbb96c23284e47927e7b6e68e183de0a1b65dab38ed1c67b78616aaf58c8d` | `reconstructed from R0 evidence/rocky/dnf4-absent-preview.txt` |
| `dnf4_tcpdump.err` | `ef85c504e13efa4224adc256f925fa9bdc9ea58f684eb61c270ce1bc8fa85f8f` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw/p3-tcpdump-default.err` |
| `dnf4_tcpdump.out` | `cca9694ffba9de781e044215e99b425919ad635225d980fe87e4a1a5345662de` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw/p3-tcpdump-default.out` |
| `dnf4_tcpdump_noauto.err` | `ef85c504e13efa4224adc256f925fa9bdc9ea58f684eb61c270ce1bc8fa85f8f` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw/p4-tcpdump-noautoremove.err` |
| `dnf4_tcpdump_noauto.out` | `9565acd45b171ddbaceb12a3fe402257daab84d3e695d5844d11ca0d560eb860` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw/p4-tcpdump-noautoremove.out` |
| `dnf4_unzip.err` | `ef85c504e13efa4224adc256f925fa9bdc9ea58f684eb61c270ce1bc8fa85f8f` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw/p1-unzip-default.err` |
| `dnf4_unzip.out` | `c7bfb6b089918878d04515fa58ddd44b6713f9b8edadfd7a788b333bac4cacfc` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw/p1-unzip-default.out` |
| `dnf4_unzip_noauto.err` | `ef85c504e13efa4224adc256f925fa9bdc9ea58f684eb61c270ce1bc8fa85f8f` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw/p2-unzip-noautoremove.err` |
| `dnf4_unzip_noauto.out` | `c7bfb6b089918878d04515fa58ddd44b6713f9b8edadfd7a788b333bac4cacfc` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw/p2-unzip-noautoremove.out` |
| `dnf5_absent.err` | `b1c4f40b979d798daed61ae2840459966366e58e81a0c79cebc6ffd58a3aa920` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p5-absent.err` |
| `dnf5_absent.out` | `e737f1678a14aed678f7709dde790730512889edac8fff44cf5e91383ec7c4c8` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p5-absent.out` |
| `dnf5_tcpdump_1.err` | `81f6d1c50b8659cbfbc748682f8c4a6cc3fe526d0079050f7e4e80198e879fba` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p4-tcpdump-noautoremove.err` |
| `dnf5_tcpdump_1.out` | `8aa969311c890673ceb395faf0858f83e4d577013f3e043398a884f21e681a38` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p4-tcpdump-noautoremove.out` |
| `dnf5_tcpdump_3.err` | `7ff2cbc0dc2189e662aa1fcbf983b676a130ab933c329195aefa331a846c8ab6` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p3-tcpdump-default.err` |
| `dnf5_tcpdump_3.out` | `f4e6b1648612832aba713cebf950f5178e87a689fca79b414f8971f88186efd9` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p3-tcpdump-default.out` |
| `dnf5_unzip_44.err` | `750f2567293c434b1e35e4b43b94dc252373a28a324ff4be00a0801958f723bf` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p1-unzip-default.err` |
| `dnf5_unzip_44.out` | `11c7395f13996c7367e9095c0de672b6b306e99d73598233004ffbf3f26b24ec` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p1-unzip-default.out` |
| `dnf5_unzip_8.err` | `1574314665ca5e7f985597b8d74edeb59e2203d4be40c74d75ad19aa24e90081` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p2-unzip-noautoremove.err` |
| `dnf5_unzip_8.out` | `6c2ef51ff54e3c79b6813e3050042e7cbe1c1573ec944523fcf19ef18698e27b` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw/p2-unzip-noautoremove.out` |
| `inventory_fedora_baseline.tsv` | `64c9693e4286acfbe233eeec551ee61f4fcd226a1e2ac6fde38eb4c83b13c341` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/fedora/raw-baseline-inventory.txt` |
| `inventory_rocky_baseline.tsv` | `8189bd9aef3c86e7d7060544d480984757b718dd94477bbd2bded9bcb6936f6a` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/rocky/raw-baseline-inventory.txt` |
| `inventory_ubuntu_baseline.tsv` | `c063329d69b8a83cbf9c5974ef7bc6f6ead4b31d65998238e5ca30c1e1e53965` | `audit-artifacts/wp-pkg-removal-preview-r0-20261023/evidence/ubuntu/raw/inv-baseline.txt` |
