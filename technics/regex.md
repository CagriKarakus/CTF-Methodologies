Escape Character:    \. ile yapınca noktayı karakter olarak arıyor yoksa nokta her karakterin yerine geçen bir joker olarak kullanılırdı. \ karakteri bize bu wildcardları normal bir karakter olarak arayabilmemizi sağlıyor.

matching specific characters :  [abc] a ya da b ya da c eşleşiyor mu ayrı ayrı eşleştirip sonuç çıkartır.

[^b]ab bize tam tersini yapar b nin eşlenmediği ab ile devam edeni getirir. bab mab kelimeleri olsun bize mab getirir çünkü b exclude charcter

Köşeli parantez notasyonunu kullanırken, tire işaretini karakter aralığını belirtmek için kullanarak ardışık karakterler listesindeki bir karakterle eşleşmeyi sağlayan bir kısayol vardır. Örneğin, [0-6] kalıbı yalnızca sıfırdan altıya kadar olan tek haneli karakterlerle eşleşir, başka hiçbir şeyle eşleşmez. Benzer şekilde, [^n-p] kalıbı da n ile p arasındaki harfler hariç olmak üzere herhangi bir tek karakterle eşleşir.

