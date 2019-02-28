# How to reproduce the problem

## Build and run

```
~ javac src/main/java/JDKSSLUnwrapReproducer.java -d target
~ java -cp target/:src/main/resources/ JDKSSLUnwrapReproducer`
```

This will execute without an error when using Java11 and older but fail on Java12 and newer.

