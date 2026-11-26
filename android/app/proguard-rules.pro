# Preserve Go/JNI boundary classes, callback interfaces, and generic signatures under R8 full-mode.
-keepattributes InnerClasses,Signature,Exceptions

-keep class mobilecore.** { *; }
-keepclassmembers class mobilecore.** { *; }
-keep interface mobilecore.** { *; }

-keep class go.** { *; }
-keepclassmembers class go.** { *; }
-keep interface go.** { *; }

-keep class com.netshaper.mobile.engine.GoMobileNetShaperEngine { *; }
-keep class com.netshaper.mobile.engine.GoMobileNetShaperEngine$Bindings { *; }

-dontwarn mobilecore.**
-dontwarn go.**
