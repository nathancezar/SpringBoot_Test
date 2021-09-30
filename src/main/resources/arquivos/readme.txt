Código usado no linux para extrair o documento do arquivo .p7s:

openssl smime -inform DER -verify -noverify -in signedDoc.p7s -out signedDoc.txt
