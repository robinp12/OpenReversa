package openreversa;

import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

/**
 * @author Robin Paquet and Arnaud Delcorte
 * 
 * Data structure for functions with various properties.
 */
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

    /**
     * Retrieves the user associated with the item.
     *
     * @return The user.
     */
    public String getUser() {
        return user;
    }

    /**
     * Retrieves the full hash value.
     *
     * @return The full hash value.
     */
    public Long getFullHash() {
        return fullHash;
    }

    /**
     * Retrieves the library family name text field.
     *
     * @return The library family name text field.
     */
    public String getLibraryFamilyNameTextField() {
        return libraryFamilyNameTextField;
    }

    /**
     * Retrieves the version text field.
     *
     * @return The version text field.
     */
    public String getVersionTextField() {
        return versionTextField;
    }

    /**
     * Retrieves the variant text field.
     *
     * @return The variant text field.
     */
    public String getVariantTextField() {
        return variantTextField;
    }

    /**
     * Retrieves the application version.
     *
     * @return The application version.
     */
    public String getApp_version() {
        return app_version;
    }

    /**
     * Retrieves the language ID.
     *
     * @return The language ID.
     */
    public LanguageID getLang_id() {
        return lang_id;
    }

    /**
     * Retrieves the language version.
     *
     * @return The language version.
     */
    public int getLang_ver() {
        return lang_ver;
    }

    /**
     * Retrieves the language minor version.
     *
     * @return The language minor version.
     */
    public int getLang_minor_ver() {
        return lang_minor_ver;
    }

    /**
     * Retrieves the compiler specification ID.
     *
     * @return The compiler specification ID.
     */
    public CompilerSpecID getCompiler_spec() {
        return compiler_spec;
    }

    /**
     * Retrieves the function name.
     *
     * @return The function name.
     */
    public String getFun_name() {
        return fun_name;
    }

    /**
     * Retrieves the function signature.
     *
     * @return The function signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Retrieves the function entry point.
     *
     * @return The function entry point.
     */
    public long getFun_entry() {
        return fun_entry;
    }

    /**
     * Retrieves the token group.
     *
     * @return The token group.
     */
    public String getTokgroup() {
        return tokgroup;
    }

    /**
     * Retrieves the code unit size.
     *
     * @return The code unit size.
     */
    public short getCodeUnitSize() {
        return codeUnitSize;
    }

    /**
     * Retrieves the additional size of the specific hash.
     *
     * @return The additional size of the specific hash.
     */
    public byte getSpecificHashAdditionalSize() {
        return specificHashAdditionalSize;
    }

    /**
     * Retrieves the specific hash value.
     *
     * @return The specific hash value.
     */
    public long getSpecificHash() {
        return specificHash;
    }

    /**
     * Retrieves the comment associated with the item.
     *
     * @return The comment.
     */
    public String getComment() {
        return comment;
    }
}