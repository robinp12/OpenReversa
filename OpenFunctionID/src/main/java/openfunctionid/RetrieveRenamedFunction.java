package openfunctionid;

/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Create multiple libraries in a single FID database
//  A root is chosen as a folder within the active project
//  Subfolders at a specific depth from this root form the roots of individual libraries
//    Library Name, Version, and Variant are created from the directory path elements
//@category FunctionID

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map.Entry;

import javax.swing.*;
import java.util.TreeSet;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.feature.fid.service.FidPopulateResultReporter;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.service.Location;
import ghidra.feature.fid.service.MatchNameAnalysis;
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


public class RetrieveRenamedFunction extends GhidraScript {


    private FidService service;
    private MatchNameAnalysis matchAnalysis;
    private FidDB fidDb = null;
    private boolean isCancelled = false;

    private FileOutputStream outlog = null;


    private TaskMonitor monitor = new TaskMonitorAdapter();


    private String libraryFamilyNameTextField;
    private String versionTextField;
    private String variantTextField;

    public RetrieveRenamedFunction(String libraryFamilyNameTextField, String versionTextField, String variantTextField) {
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

    public RetrieveRenamedFunction() {
		// TODO Auto-generated constructor stub
	}
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

    class MyFidPopulateResultReporter implements FidPopulateResultReporter {
        @Override
        public void report(FidPopulateResult result) {
            if (result == null) {
                return;
            }
            LibraryRecord libraryRecord = result.getLibraryRecord();
            String libraryFamilyName = libraryRecord.getLibraryFamilyName();
            String libraryVersion = libraryRecord.getLibraryVersion();
            String libraryVariant = libraryRecord.getLibraryVariant();
            outputLine(libraryFamilyName + ':' + libraryVersion + ':' + libraryVariant);

            outputLine(result.getTotalAttempted() + " total functions visited");
            outputLine(result.getTotalAdded() + " total functions added");
            outputLine(result.getTotalExcluded() + " total functions excluded");
            outputLine("Breakdown of exclusions:");
            for (Entry<Disposition, Integer> entry : result.getFailures().entrySet()) {
                if (entry.getKey() != Disposition.INCLUDED) {
                    outputLine("    " + entry.getKey() + ": " + entry.getValue());
                }
            }
            outputLine("List of unresolved symbols:");
            TreeSet<String> symbols = new TreeSet<String>();
            for (Location location : result.getUnresolvedSymbols()) {
                symbols.add(location.getFunctionName());
            }
            for (String symbol : symbols) {
                outputLine("    " + symbol);
            }
        }

    }

    protected void findPrograms(ArrayList<DomainFile> programs, DomainFolder myFolder)
            throws CancelledException {
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (VersionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
    }

    public void pushToDB() throws MemoryAccessException {
        ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
        service = new FidService();
        matchAnalysis = new MatchNameAnalysis();

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


                //System.out.println(app_version);

                //System.out.println(compiler_spec);
                //System.out.println(lang_id);
                //System.out.println(lang_ver);
                //System.out.println(lang_minor_ver);
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
                        System.out.println("passe pas : " + function.getName());

                        continue; // No body
                    }
                    MessageDigest digest = new FNV1a64MessageDigest();
                    digest.update(function.getName().getBytes(), TaskMonitor.DUMMY);
                    digest.update(hashFunction.getFullHash());

                    FidHashQuad fid = new FidHashQuadImpl(hashFunction.getCodeUnitSize(), hashFunction.getFullHash(), hashFunction.getSpecificHashAdditionalSize(), hashFunction.getSpecificHash());
                    //System.out.println(hashFunction.getCodeUnitSize());
                    //System.out.println(hashFunction.getFullHash());
                    //System.out.println(hashFunction.getSpecificHashAdditionalSize());
                    //System.out.println(hashFunction.getSpecificHash());

                    String fun_name = function.getName();
                    long fun_entry = function.getEntryPoint().getOffset();

                    //System.out.println(function.getEntryPoint());

                    System.out.println(function.getSignature());

                    //System.out.println(fun_name);
                    //System.out.println(function.getName().getBytes());
                    //System.out.println(function.getSignature());
                    //System.out.println("FID Hash for " + fun_name + " at " + function.getEntryPoint() + ": " + hashFunction.toString());

                    DecompInterface ifc = new DecompInterface();
                    ifc.openProgram(program);
                    DecompileResults res = ifc.decompileFunction(function, 0, monitor);
                    // Check for error conditions
                    if (!res.decompileCompleted()) {
                        System.out.println(res.getErrorMessage());
                        return;
                    }
                    DecompiledFunction tokgroup = res.getDecompiledFunction();
                    //System.out.println(tokgroup.getC());

                    item = new MyItem("", hashFunction.getCodeUnitSize(), hashFunction.getFullHash(),
                            hashFunction.getSpecificHashAdditionalSize(), hashFunction.getSpecificHash(),
                            libraryFamilyNameTextField, versionTextField,
                            variantTextField, app_version, lang_id,
                            lang_ver, lang_minor_ver, compiler_spec,
                            fun_name, fun_entry, tokgroup.getC().toString());
                    output.add(item);
                    //sendPOST(hashFunction.getFullHash(), libraryFamilyNameTextField, versionTextField, variantTextField, app_version, lang_id, lang_ver, lang_minor_ver, compiler_spec, hashFunction, fun_name, fun_entry, tokgroup);

                }
                Selection dialog = new Selection(output, true);
                JDialog jDialog = new JDialog();

                jDialog.setModal(true);
                jDialog.setTitle("Select Functions to share");
                jDialog.getContentPane().add(dialog.getComponent());
                jDialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
                jDialog.pack();
                jDialog.setLocationRelativeTo(null);
                jDialog.setVisible(true);


            }
        } catch (CancelledException | IOException | VersionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @Override
    protected void run() throws Exception {
        //getAllModifiedFunc();
        pushToDB();
    }

}