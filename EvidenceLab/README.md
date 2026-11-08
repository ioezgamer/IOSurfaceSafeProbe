# IOSurface Evidence Lab

App iOS para comprobar exclusivamente llamadas publicas IOSurface sobre buffers propios y auditar afirmaciones en logs.

No implementa UAF, kernel read/write, bypass de KASLR o de SPTM.

La IPA se produce sin firma mediante GitHub Actions. Debe firmarse con SideStore/AltStore o con una identidad propia antes de instalarse en un iPhone.
