package openreversa;

import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

public class MyItem {
    private String user;

    private Long fullHash;
    private short codeUnitSize;
    private byte specificHashAdditionalSize;
    private long specificHash;

    private String libraryFamilyNameTextField;
    private String versionTextField;
    private String variantTextField;

    private String app_version;
    private LanguageID lang_id;
    private int lang_ver;
    private int lang_minor_ver;
    private CompilerSpecID compiler_spec;
    private String fun_name;
    private long fun_entry;
    private String tokgroup;
	private String signature;
	private String comment;


    public MyItem(String user, short codeUnitSize, long fullHash,
                  byte specificHashAdditionalSize, long specificHash,
                  String libraryFamilyNameTextField, String versionTextField,
                  String variantTextField, String app_version, LanguageID lang_id,
                  int lang_ver, int lang_minor_ver, CompilerSpecID compiler_spec,
                  String fun_name, long fun_entry, String signature, String tokgroup, String comment) {
        this.user = user;

        this.codeUnitSize = codeUnitSize;
        this.fullHash = fullHash;
        this.specificHashAdditionalSize = specificHashAdditionalSize;
        this.specificHash = specificHash;

        this.libraryFamilyNameTextField = libraryFamilyNameTextField;
        this.versionTextField = versionTextField;
        this.variantTextField = variantTextField;
        this.app_version = app_version;
        this.lang_id = lang_id;
        this.lang_ver = lang_ver;
        this.lang_minor_ver = lang_minor_ver;
        this.compiler_spec = compiler_spec;
        this.fun_name = fun_name;
        this.signature = signature;
        this.fun_entry = fun_entry;
        this.tokgroup = tokgroup;
        this.comment = comment;
    }


    public String getUser() {
        return user;
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

    public String getFun_name() {
        return fun_name;
    }
    
    public String getSignature() {
        return signature;
    }

    public long getFun_entry() {
        return fun_entry;
    }

    public String getTokgroup() {
        return tokgroup;
    }


    public short getCodeUnitSize() {
        return codeUnitSize;
    }


    public byte getSpecificHashAdditionalSize() {
        return specificHashAdditionalSize;
    }


    public long getSpecificHash() {
        return specificHash;
    }

    public String getComment() {
        return comment;
    }
}
