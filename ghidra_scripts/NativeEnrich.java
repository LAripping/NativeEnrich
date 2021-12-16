//This script reads both frida output AND FindNativeJNIMethods output,
//to enrich the binary with named and typed native functions identified within an APK

//@author laripping
//@category JNI
//@keybinding
//@menupath
//@toolbar

import generic.jar.ResourceFile;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.Application;


import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

public class NativeEnrich extends GhidraScript {

    DataTypeManager manager;

    private class MethodInformation {
        private String methodName;
        private String argumentSignature;
        private ArrayList<String> argumentTypes;
        private String returnType;
        private boolean isStatic;

        private String ghidraOffset;        // the only field that will come from the second file
    }
    /**
     * Wrapper class only to be passed to JSON parsers
     * for one-step deserialisation
     */
    private class MethodInformationCollection {
        ArrayList<MethodInformation> methods = new ArrayList<>();
    }


    @Override
    public void run() throws Exception {
        println("[+] Import jni_all.h...");
        this.manager = getDataTypeManageFromArchiveFile();

        // First, we ask for `nativeMethods-jar.json`
        // the fat file that came out of the JAR, carrying all methodInfo as extracted
        File firstFile = this.askFile("Select nativeMethods-jar.json", "Open");
        Gson gson = new Gson();
        JsonReader reader = new JsonReader(new FileReader(firstFile));
        MethodInformationCollection ayrxMethodInfo = gson.fromJson(reader, MethodInformationCollection.class);
        println("[+] Loaded " + ayrxMethodInfo.methods.size() + " functions from the APK (from all libs)");

        // Second, we ask for `nativeMethods-frida.json`
        // the frida output, carrying the GhidraOffsets, and the full method name as a key
        File secondFile = this.askFile("Select nativeMethods-frida.json", "Open");
        reader = new JsonReader(new FileReader(secondFile));
        MethodInformationCollection fridaMethodInfo = gson.fromJson(reader, MethodInformationCollection.class);
        println("[+] Loaded " + fridaMethodInfo.methods.size() + " functions by frida (from our lib only)");

        MethodInformationCollection completeMethodInfo = new MethodInformationCollection();
        for (MethodInformation slimObj : fridaMethodInfo.methods) {
            boolean found = false;          // any uses for this?
            for (MethodInformation fatObj : ayrxMethodInfo.methods) {
                if (fatObj.methodName.equals(slimObj.methodName)) {
                    // Merge the ayrx JSON object with the ghidraOffset
                    // from its associated frida JSON object
                    fatObj.ghidraOffset = slimObj.ghidraOffset;
                    completeMethodInfo.methods.add(fatObj);
                    println(String.format("[+] Added ghidraOffset:%s to method:%s", fatObj.ghidraOffset, fatObj.methodName));
                    found = true;
                    break;   // exit second loop
                }
            }
        }
        println("[+] Merged lists and ended up with " + completeMethodInfo.methods.size() + " functions");

        // Start walking the binary at ghidraOffsets
        for(MethodInformation obj : completeMethodInfo.methods){
            Address a = currentAddress.getAddress(obj.ghidraOffset);
            Function f = getFunctionAt(a);
            if(f==null){
                println("[!] Failed to getFunctionAt("+a.toString()+")");
                return;
            }
            applyFunctionSignature(obj,f);  // and rename/retype the func in each location
        }
    }


    /**
     * Just like in Ayrx's code,
     * @param methodInfo   the info we extracted from both JSON Ayrx's FindNativeJNILibs.jar and Frida
     * @param f the Ghidra function pointer
     * @throws InvalidInputException
     * @throws DuplicateNameException
     */
    private void applyFunctionSignature(MethodInformation methodInfo, Function f)
            throws InvalidInputException, DuplicateNameException {

        Parameter[] params = new Parameter[methodInfo.argumentTypes.size() + 2]; // + 2 to accomodate env and thiz

        params[0] = new ParameterImpl(
                "env",
                this.manager.getDataType("/jni_all.h/JNIEnv *"),
                this.currentProgram,
                SourceType.USER_DEFINED
        );

        params[1] = new ParameterImpl(
                "thiz",     // we could rename this according to the className...
                methodInfo.isStatic
                        ? this.manager.getDataType("/jni_all.h/jclass")
                        : this.manager.getDataType("/jni_all.h/jobject"),
                this.currentProgram,
                SourceType.USER_DEFINED
        );

        for (int i = 0; i < methodInfo.argumentTypes.size(); i++) {
            String argType = methodInfo.argumentTypes.get(i);

            params[i + 2] = new ParameterImpl(
                    "a" + String.valueOf(i),
                    this.manager.getDataType("/jni_all.h/" + argType),
                    this.currentProgram,
                    SourceType.USER_DEFINED
            );
        }

        Parameter returnType = new ReturnParameterImpl(
                this.manager.getDataType("/jni_all.h/" + methodInfo.returnType),
                this.currentProgram
        );

        String[] parts = methodInfo.methodName.split("\\.");
        f.setName(
                parts[parts.length-1],
                SourceType.USER_DEFINED
        );

        f.updateFunction(
                null,
                returnType,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true,
                SourceType.USER_DEFINED,
                params
        );


    }

    public DataTypeManager getDataTypeManageFromArchiveFile() throws IOException, DuplicateIdException {
        DataTypeManagerService service = this.state.getTool().getService(DataTypeManagerService.class);

        // Look for an already open "jni_all" archive.
        DataTypeManager[] managers = service.getDataTypeManagers();
        for (DataTypeManager m : managers) {
            if (m.getName().equals("jni_all")) {
                return m;
            }
        }

        // If an existing archive isn't found, open it from the file.
        ResourceFile jniArchiveFile = Application.getModuleDataFile("NativeEnrich", "jni_all.gdt");
        Archive jniArchive = service.openArchive(jniArchiveFile.getFile(true), false);
        return jniArchive.getDataTypeManager();
    }

}
