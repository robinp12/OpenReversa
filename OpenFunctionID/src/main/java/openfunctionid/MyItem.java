package openfunctionid;

import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

public class MyItem {
    private Long fullHash;
    private String libraryFamilyNameTextField;
    private String versionTextField;
    private String variantTextField;
    private String app_version;
    private LanguageID lang_id;
    private int lang_ver;
    private int lang_minor_ver;
    private CompilerSpecID compiler_spec;
    private FidHashQuad hashFunction;
    private String fun_name;
    private long fun_entry;
    private ClangTokenGroup tokgroup;

    public MyItem(Long fullHash, String libraryFamilyNameTextField, String versionTextField, String ariantTextField, String app_version, LanguageID lang_id, int lang_ver, int lang_minor_ver, CompilerSpecID compiler_spec, FidHashQuad hashFunction, String fun_name, long fun_entry, ClangTokenGroup tokgroup) {
        this.fullHash = fullHash; 
        this.libraryFamilyNameTextField = libraryFamilyNameTextField; 
        this.versionTextField = versionTextField; 
        this.variantTextField = ariantTextField; 
        this.app_version = app_version;
        this.lang_id = lang_id; 
        this.lang_ver = lang_ver; 
        this.lang_minor_ver = lang_minor_ver; 
        this.compiler_spec = compiler_spec; 
        this.hashFunction = hashFunction;
        this.fun_name = fun_name; 
        this.fun_entry = fun_entry; 
        this.tokgroup = tokgroup;
    }

    public Long getFullHash() {
        return fullHash;
    }

    public String getLibraryFamilyNameTextField() {
        return libraryFamilyNameTextField;
    }

    public String getVersionTextField() {
        return versionTextField;
    }

    public String getVariantTextField() {
        return variantTextField;
    }

    public String getApp_version() {
        return app_version;
    }

    public LanguageID getLang_id() {
        return lang_id;
    }

    public int getLang_ver() {
        return lang_ver;
    }

    public int getLang_minor_ver() {
        return lang_minor_ver;
    }

    public CompilerSpecID getCompiler_spec() {
        return compiler_spec;
    }
    
    public FidHashQuad getHashFunction() {
        return hashFunction;
    }

    public String getFun_name() {
        return fun_name;
    }

    public long getFun_entry() {
        return fun_entry;
    }

    public ClangTokenGroup getTokgroup() {
        return tokgroup;
    }
}
