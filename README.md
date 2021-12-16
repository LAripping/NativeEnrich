# Native Enrich

A Ghidra script to aid reverse engineering of Android native (.so) libraries, by identifying dynamically registered functions within the Code Listing.

In effect: going from this

```c++
void FUN_00905b34 (undefined8 param_1, undefined8 param_2)
```

to this

```c++
jboolean handleOnClick (JNIEnv* env, jobject thiz, jobject a0, jobject a1, jint a2, jint a3)
```



## How to install the extension

1. Clone this repository 

   ```bash
   $ git clone https://github.com/laripping/NativeEnrich.git && cd NativeEnrich
   ```

2. Build the script, pointing Graddle to your Ghidra installation directory

   >  ...as our [build.graddle](build.graddle) is just a wrapper of Ghidra's bundled Extension compiler 

   ```bash
   $ gradle -PGHIDRA_INSTALL_DIR=<YOUR GHIDRA INSTALLATION DIRECTORY>
   ```

   You should now have a sleek ZIP file in your `dist/` directory

3. Import the script in Ghidra from the Projects Window

   `File > Install Extensions... >  choose the ZIP file`

4. Restart Ghidra as prompted



:information_source: The complete flow listed above is needed at least once to bundle the GSON library and populate the Java classes in Ghidra's directories. Further changes to the main file `ghidra_scripts/NativeEnrich.java` can then be made on the fly using Ghidra's Script Manager, and selecting the "Edit script with basic editor" button on the top right