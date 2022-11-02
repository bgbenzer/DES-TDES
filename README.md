# DES-TripleDES


to Compile:
```javac FileCipher.java```



Methods Available:

1) DES (for DES)
2) 3DES (for TripleDES)

Modes Available:

*Available for both DES and TripleDES*
1) CBC
2) CFB
3) OFB
4) CTR



to Encrypt:
```java FileCipher -e -i *inputFile* -o *outputFile* *Method* *Mode* *keyFile*```

to Decrypt:
```java FileCipher -d -i *inputFile* -o *outputFile* *Method* *Mode* *keyFile*```


You can give argument files as path
