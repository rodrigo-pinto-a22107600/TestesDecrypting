### Problemas:

Não encontramos maneira de mudar o PKCS5Padding para PKCS7 como o Fernando utiliza na linha seguinte
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); (Linha )  
Segundo o que nós procuramos o PKCS7 não é dos Padding que vem já com o Java

Não sabemos bem como criar o array de IV, o Fernando apenas faz um comando e gera o array  
aesman.Key = rfc2898.GetBytes(aesman.KeySize / 8)  
aesman.IV = rfc2898.GetBytes(aesman.BlockSize / 8)  
Esse array muda com cada execução e nós não tivemos sucesso em recriá-lo  



### O que sabemos:
RFC 2898  
SHA1  
AES/CBC  
PKCS7  
KeySize = 256  
BlockSize = 128  
