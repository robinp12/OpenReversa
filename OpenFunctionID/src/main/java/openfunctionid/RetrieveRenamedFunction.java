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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.TreeSet;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.FunctionRecord;
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
	private FidFile fidFile  = null;
	private boolean isCancelled = false;

	//private String[] pathelement;
	private String currentLibraryName;
	private String currentLibraryVersion;
	private String currentLibraryVariant;

	private TreeMap<Long, String> duplicatemap = null;
	private FileOutputStream outlog = null;
	private File commonSymbolsFile = null;
	private List<String> commonSymbols = null;
	private LanguageID languageID = null;

	private MyFidPopulateResultReporter reporter = null;

	private static final int MASTER_DEPTH = 3;
	private TaskMonitor monitor = new TaskMonitorAdapter();

	protected void outputLine(String line) {
		if (outlog != null) {
			try {
				outlog.write(line.getBytes());
				outlog.write('\n');
				outlog.flush();
			}
			catch (IOException e) {
				println("Unable to write to log");
			}
		}
		else {
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

	private void hashFunction(Program program, ArrayList<Long> hashList)
			throws MemoryAccessException, CancelledException {
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator functions = functionManager.getFunctions(true);
		while (functions.hasNext()) {
			monitor.checkCanceled();
			Function func = functions.next();
			FidHashQuad hashFunction = service.hashFunction(func);
			if (hashFunction == null) {
				continue; // No body
			}
			MessageDigest digest = new FNV1a64MessageDigest();
			digest.update(func.getName().getBytes(), TaskMonitor.DUMMY);
			digest.update(hashFunction.getFullHash());
			hashList.add(digest.digestLong());
		}
	}

	private void hashListProgram(DomainFile domainFile, ArrayList<Long> hashList)
			throws VersionException, CancelledException, IOException, MemoryAccessException {
		DomainObject domainObject = null;
		try {
			domainObject = domainFile.getDomainObject(this, false, true, TaskMonitor.DUMMY);
			if (!(domainObject instanceof Program)) {
				return;
			}
			Program program = (Program) domainObject;
			hashFunction(program, hashList);
		}
		finally {
			if (domainObject != null) {
				domainObject.release(this);
			}
		}

	}

	private long calculateFinalHash(ArrayList<Long> hashList) throws CancelledException {
		MessageDigest digest = new FNV1a64MessageDigest();
		Collections.sort(hashList);
		for (int i = 0; i < hashList.size(); ++i) {
			monitor.checkCanceled();
			digest.update(hashList.get(i));
		}
		return digest.digestLong();
	}

	private boolean checkForDuplicate(ArrayList<DomainFile> programs) throws CancelledException {
		String fullName =
			currentLibraryName + ':' + currentLibraryVersion + ':' + currentLibraryVariant;
		ArrayList<Long> hashList = new ArrayList<Long>();
		for (int i = 0; i < programs.size(); ++i) {
			monitor.checkCanceled();
			try {
				System.out.println(programs.get(i));
				hashListProgram(programs.get(i), hashList);
			}
			catch (VersionException ex) {
				outputLine("Version exception for " + fullName);
			}
			catch (IOException ex) {
				outputLine("IO exception for " + fullName);
			}
			catch (MemoryAccessException ex) {
				outputLine("Memory access exception for " + fullName);
			}
		}
		long val = calculateFinalHash(hashList);
		String string = duplicatemap.get(val);
		boolean res;
		if (string != null) {
			outputLine(fullName + " duplicates " + string);
			res = true;
		}
		else {
			duplicatemap.put(val, fullName);
			res = false;
		}
		return res;
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
	
	public void getAllModifiedFunc() throws CancelledException, MemoryAccessException {
		ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
		service = new FidService();
		matchAnalysis = new MatchNameAnalysis();

		try {
			findPrograms(programs, getProjectRootFolder());
			System.out.println(programs);
			for (DomainFile program1 : programs) {
				DomainObject domainObject = null;
				domainObject = program1.getDomainObject(this, false, true, TaskMonitor.DUMMY);
				if (!(domainObject instanceof Program)) {
					return;
				}
					
				Program program = (Program) domainObject;
				FunctionManager functionManager = program.getFunctionManager();
				
				System.out.println(Application.getApplicationVersion());
				
				System.out.println(program.getProgramUserData());

				
				System.out.println(program.getCompilerSpec().getCompilerSpecID());
				System.out.println(program.getLanguageID());
				System.out.println(program.getLanguage().getVersion());
				System.out.println(program.getLanguage().getMinorVersion());
				//System.out.println(program.getLanguage().getAddressFactory().getDefaultAddressSpace());
				
				//System.out.println(program.getProgramUserData());
				
				FunctionIterator functions = functionManager.getFunctions(true);
				for (Function function : functions) {
					if (monitor.isCancelled()) {
						return;
					}
					if(function.getName().startsWith("FUN_") || function.getName().startsWith("Ordinal_")) {
						continue;
					}
					FidHashQuad hashFunction = service.hashFunction(function);
					if (hashFunction == null) {
						continue; // No body
					}
					MessageDigest digest = new FNV1a64MessageDigest();
					digest.update(function.getName().getBytes(), TaskMonitor.DUMMY);
					digest.update(hashFunction.getFullHash());
					
					System.out.println(hashFunction.getCodeUnitSize());
					System.out.println(hashFunction.getFullHash());
					System.out.println(hashFunction.getSpecificHashAdditionalSize());
					System.out.println(hashFunction.getSpecificHash());

					System.out.println(function.getEntryPoint());
					System.out.println(function.getName());
					//System.out.println(function.getName().getBytes());
					System.out.println(function.getSignature());
					System.out.println("FID Hash for " + function.getName() + " at " + function.getEntryPoint() + ": " +
							hashFunction.toString());
					System.out.println();
					LibraryRecord newlib = fidDb.createNewLibrary("name", "ver", "var", 
							Application.getApplicationVersion(), program.getLanguageID(), program.getLanguage().getVersion(), 
							program.getLanguage().getMinorVersion(), program.getCompilerSpec().getCompilerSpecID());
					FunctionRecord newfunc = fidDb.createNewFunction(newlib, hashFunction, function.getName(), function.getEntryPoint().getOffset() , "domainecheminAMODIFIER", false);
					DecompInterface ifc = new DecompInterface();
					ifc.openProgram(program);
					DecompileResults res = ifc.decompileFunction(function, 0, monitor);
					 // Check for error conditions
					   if (!res.decompileCompleted()) {
					        System.out.println(res.getErrorMessage());
					      return;
					   }
					   ClangTokenGroup tokgroup = res.getCCodeMarkup();
					//System.out.println(tokgroup);
				}

			}

		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			isCancelled = true;
		} catch (VersionException e) {
			// TODO Auto-generated catch block
			Msg.showError(this, null, "Version Exception",
					"One of the programs in your domain folder cannot be upgraded: " + e.getMessage());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			Msg.showError(this, null, "FidDb IOException", "Please notify the Ghidra team:", e);
		}
		try {
			fidDb.saveDatabase("Saving", monitor);
		} catch (CancelledException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally {
			fidDb.close();
		}

	}
	
	private void selectFidFile() throws CancelledException, VersionException, IOException {
		FidFileManager fidFileManager = FidFileManager.getInstance();
		List<FidFile> userFid = fidFileManager.getUserAddedFiles();
		if (userFid.isEmpty()) {
			return;
		}
		fidFile = askChoice("List Domain files", "Choose FID database", userFid, userFid.get(0));
		fidDb = fidFile.getFidDB(true);
		monitor.initialize(1);

	}
	private void populateLibrary() throws MemoryAccessException, VersionException, CancelledException, IllegalStateException, IOException {
		FidPopulateResult result = service.createNewLibraryFromPrograms(fidDb,
				currentLibraryName, currentLibraryVersion, currentLibraryVariant, null, null,
				languageID, null, commonSymbols, TaskMonitor.DUMMY);
		reporter.report(result);
	}

	@Override
	protected void run() throws Exception {
		selectFidFile();
		getAllModifiedFunc();
	}

}