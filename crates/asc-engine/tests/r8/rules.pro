-keep class com.example.shop.Main { public static void main(java.lang.String[]); }
# Keep Cart's overloads as methods (renamed) instead of letting R8 inline them.
-keepclassmembers,allowobfuscation class com.example.shop.model.Cart { public *; }
-keepattributes SourceFile,LineNumberTable
-repackageclasses 'z'
-allowaccessmodification
