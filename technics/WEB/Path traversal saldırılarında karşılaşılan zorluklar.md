---
title: "Path Traversal — Karşılaşılan Zorluklar & Bypass"
date: 2026-09-29
tags: [web, path-traversal, bypass]
---
# Path Traversal — Karşılaşılan Zorluklar & Bypass

#### traversal sequences blocked with absolute path bypass: 
The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

../../ gibi traverse edilmesini sağlayan inputlar bloklanır. ama düz /etc/passwd gibi çıktılar iş görür.

You might be able to use nested traversal sequences, such as `....//` or `....\/`. These revert to simple traversal sequences when the inner sequence is stripped.

Bazı durumlarda, örneğin bir URL yolunda veya multipart/form-data isteğinin dosya adı parametresinde, web sunucuları girdinizi uygulamaya iletmeden önce dizin geçiş dizilerini kaldırabilir. Bazen ../ karakterlerini URL kodlaması veya hatta çift URL kodlaması yaparak bu tür bir temizleme işlemini atlayabilirsiniz. Bu işlem sonucunda sırasıyla %2e%2e%2f ve %252e%252e%252f elde edilir. ..%c0%af veya ..%ef%bc%8f gibi çeşitli standart dışı kodlamalar da işe yarayabilir.



An application may require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case, it might be possible to include the required base folder followed by suitable traversal sequences. For example: `filename=/var/www/images/../../../etc/passwd`.

An application may require the user-supplied filename to end with an expected file extension, such as `.png`. In this case, it might be possible to use a null byte to effectively terminate the file path before the required extension. For example: `filename=../../../etc/passwd%00.png`.

---

**Up:** [Home](../Home.md)
**Related:** [File Inclusion - Path Traversal](File%20Inclusion%20-%20Path%20Traversal.md)
