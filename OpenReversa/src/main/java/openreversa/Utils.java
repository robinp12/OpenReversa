package openreversa;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.swing.JDialog;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.Application;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * @author Robin Paquet and Arnaud Delcorte
 * <p>
 * This class is a toolbox with various method call
 * Used to retrieves renamed functions from a FID (Function ID) database or get environment informations
 * It operates on multiple libraries in a single FID database.
 * A root folder is chosen within the active project, and subfolders at a specific depth from this root form the roots of individual libraries.
 * The Library Name, Version, and Variant are created from the directory path elements.
 * @category FunctionID
 */
public class Utils extends GhidraScript {

    private FidService service;
    private FileOutputStream outlog = null;
    private TaskMonitor monitor = new TaskMonitorAdapter();
    private String libraryFamilyNameTextField;
    private String versionTextField;

    private String variantTextField;

    /**
     * Default constructor for Utils class.
     */
    public Utils() {
    }

    /**
     * Constructor for Utils class.
     *
     * @param libraryFamilyNameTextField The library family name.
     * @param versionTextField           The library version.
     * @param variantTextField           The library variant.
     */
    public Utils(String libraryFamilyNameTextField, String versionTextField, String variantTextField) {
        this.libraryFamilyNameTextField = libraryFamilyNameTextField;
        this.versionTextField = versionTextField;
        this.variantTextField = variantTextField;

        try {
            pushToDB();
        } catch (MemoryAccessException e) {
            Msg.showError(getClass(), null, "Server error", "Sorry, the server is currently unavailable. Please try again later.");
            e.printStackTrace();
        }
    }

    /**
     * Finds programs within the given folder and adds them to the provided programs list.
     *
     * @param programs The list to store the found programs.
     * @param myFolder The folder to search for programs.
     * @throws CancelledException If the operation is cancelled.
     */
    protected void findPrograms(ArrayList<DomainFile> programs, DomainFolder myFolder) throws CancelledException {
        if (myFolder == null) {
            return;
        }
        DomainFile[] files = myFolder.getFiles();
        for (DomainFile domainFile : files) {
            monitor.checkCanceled();
            if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
                programs.add(domainFile);
            }
        }
        DomainFolder[] folders = myFolder.getFolders();
        for (DomainFolder domainFolder : folders) {
            monitor.checkCanceled();
            findPrograms(programs, domainFolder);
        }
    }


    /**
     * Retrieves the language ID of the program.
     *
     * @return The LanguageID of the program, or null if it couldn't be determined.
     */
    public LanguageID getProgramLanguage() {
        ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
        try {
            findPrograms(programs, getProjectRootFolder());
            DomainObject domainObject = null;
            domainObject = programs.get(0).getDomainObject(this, false, true, TaskMonitor.DUMMY);
            if (!(domainObject instanceof Program)) {
                return null;
            }

            Program program = (Program) domainObject;
            return program.getLanguageID();
        } catch (CancelledException e) {
            e.printStackTrace();
        } catch (VersionException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Outputs the provided line to the script console or log file.
     *
     * @param line The line to be outputted.
     */
    protected void outputLine(String line) {
        if (outlog != null) {
            try {
                outlog.write(line.getBytes());
                outlog.write('\n');
                outlog.flush();
            } catch (IOException e) {
                println("Unable to write to log");
            }
        } else {
            println(line);
        }
    }

    /**
     * Retrieve functions from program to send into the OpenReversa database.
     *
     * @throws MemoryAccessException If there is a memory access error.
     */
    public void pushToDB() throws MemoryAccessException {
        ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
        service = new FidService();

        ArrayList<String> thunkFunc = new ArrayList<>();

        try {
            findPrograms(programs, getProjectRootFolder());
            for (DomainFile program1 : programs) {
                DomainObject domainObject = null;
                domainObject = program1.getDomainObject(this, false, true, TaskMonitor.DUMMY);
                if (!(domainObject instanceof Program)) {
                    return;
                }

                Program program = (Program) domainObject;
                FunctionManager functionManager = program.getFunctionManager();

                String app_version = Application.getApplicationVersion();
                LanguageID lang_id = program.getLanguageID();
                int lang_ver = program.getLanguage().getVersion();
                int lang_minor_ver = program.getLanguage().getMinorVersion();
                CompilerSpecID compiler_spec = program.getCompilerSpec().getCompilerSpecID();

                ArrayList<MyItem> output = new ArrayList<MyItem>();
                MyItem item;
                FunctionIterator functions = functionManager.getFunctions(true);
                for (Function function : functions) {

                    if (monitor.isCancelled()) {
                        return;
                    }
                    if (function.getName().startsWith("FUN_") || function.getName().startsWith("Ordinal_")) {
                        continue;
                    }

                    FidHashQuad hashFunction = service.hashFunction(function);
                    if (hashFunction == null) {
                        thunkFunc.add(function.getSignature().toString());
                    } else if (!thunkFunc.contains(function.getSignature().toString())) {
                        MessageDigest digest = new FNV1a64MessageDigest();
                        digest.update(function.getName().getBytes(), TaskMonitor.DUMMY);
                        digest.update(hashFunction.getFullHash());

                        FidHashQuad fid = new FidHashQuadImpl(hashFunction.getCodeUnitSize(),
                                hashFunction.getFullHash(), hashFunction.getSpecificHashAdditionalSize(),
                                hashFunction.getSpecificHash());

                        String fun_name = function.getName();
                        long fun_entry = function.getEntryPoint().getOffset();
                        String signature = Base64.getEncoder()
                                .encodeToString(function.getSignature().toString().getBytes(StandardCharsets.UTF_8));

                        DecompInterface ifc = new DecompInterface();
                        ifc.openProgram(program);
                        DecompileResults res = ifc.decompileFunction(function, 0, monitor);
                        if (!res.decompileCompleted()) {
                            System.out.println(res.getErrorMessage());
                            return;
                        }
                        DecompiledFunction tokgroup = res.getDecompiledFunction();

                        item = new MyItem("", hashFunction.getCodeUnitSize(), hashFunction.getFullHash(),
                                hashFunction.getSpecificHashAdditionalSize(), hashFunction.getSpecificHash(),
                                libraryFamilyNameTextField, versionTextField, variantTextField, app_version, lang_id,
                                lang_ver, lang_minor_ver, compiler_spec, fun_name, fun_entry, signature,
                                tokgroup.getC().toString(), "");
                        output.add(item);
                    }
                }
                SelectionDialog dialog = new SelectionDialog(output, true);
                JDialog jDialog = new JDialog();
                String excluded_func = "";
                for (int i = 0; i < thunkFunc.size(); i++) {
                    excluded_func += thunkFunc.get(i) + "\n";
                }

                Msg.showInfo(getClass(), null, "Function excluded",
                        thunkFunc.size() + " function(s) excluded : \n" + excluded_func);

                jDialog.setModal(true);
                jDialog.setTitle("Select Functions to share");
                jDialog.getContentPane().add(dialog.getComponent());
                jDialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
                jDialog.pack();
                jDialog.setLocationRelativeTo(null);
                jDialog.setVisible(true);
            }
        } catch (CancelledException e) {
            e.printStackTrace();
        } catch (VersionException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Choose fidb file to link in order to add function from database
     *
     * @return linked fidb file
     * @throws CancelledException
     * @throws VersionException
     * @throws IOException
     */
    public FidDB selectFidFile() throws CancelledException, VersionException, IOException {
        FidFileManager fidFileManager = FidFileManager.getInstance();
        List<FidFile> userFid = fidFileManager.getUserAddedFiles();
        if (userFid.isEmpty()) {
            return null;
        }
        FidFile fidFile = askChoice("Choose Fidb file", "Choose FID database to populate", userFid, userFid.get(0));
        FidDB fidDb = fidFile.getFidDB(true);
        return fidDb;
    }

    @Override
    protected void run() throws Exception {
        // TODO Auto-generated method stub

    }
}