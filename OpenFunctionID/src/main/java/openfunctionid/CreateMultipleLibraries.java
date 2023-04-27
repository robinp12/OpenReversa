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
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
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
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.feature.fid.service.FidPopulateResultReporter;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.service.Location;
import ghidra.framework.Application;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
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

public class CreateMultipleLibraries extends GhidraScript {

	private FidService service;
	private FidDB fidDb = null;
	private FidFile fidFile = null;
	private DomainFolder rootFolder = null;
	private int totalLibraries = 0;
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

	private boolean detectDups(DomainFolder folder) {
		boolean isDuplicate = false;
		try {
			ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
			findPrograms(programs, folder);

			isDuplicate = checkForDuplicate(programs);
		}
		catch (CancelledException e) {
			// cancelled by user; don't notify
			isCancelled = true;
		}
		return isDuplicate;
	}

	private void createLibraryNames() {
		// path should look like : compiler, project, version, options
		currentLibraryName = "Ceci";
		currentLibraryVersion = "Est";
		//currentLibraryVariant = pathelement[0] + ':' + pathelement[3];
		currentLibraryVariant = "Test";
	}

	private void parseSymbols() throws IOException, CancelledException {
		if (commonSymbolsFile == null) {
			commonSymbols = null;
			return;
		}
		BufferedReader reader = new BufferedReader(new FileReader(commonSymbolsFile));
		commonSymbols = new LinkedList<String>();
		String line = reader.readLine();
		while (line != null) {
			monitor.checkCanceled();
			if (line.length() != 0) {
				commonSymbols.add(line);
			}
			line = reader.readLine();
		}
		reader.close();
	}

	private void countLibraries(int depth, DomainFolder fold) {
		if (depth == 0) {
			totalLibraries += 1;
			return;
		}
		depth -= 1;
		DomainFolder[] subfold = fold.getFolders();
		for (DomainFolder element : subfold) {
			countLibraries(depth, element);
		}
	}

	/**
	 * Recursively finds all domain objects that are program files under a domain folder.
	 * @param programs the "return" value; found programs are placed in this collection
	 * @param myFolder the domain folder to search
	 * @throws CancelledException if the user cancels
	 */
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
	
	
	public void recupAll() throws CancelledException, MemoryAccessException {
		ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
		service = new FidService();
		DomainFolder folder = getProjectRootFolder();

		try {
			findPrograms(programs, folder);
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
					System.out.println(function.getName().getBytes());
					System.out.println(function.getSignature());
					System.out.println();
					
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
			e.printStackTrace();
		} catch (VersionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	private void populateLibrary(DomainFolder folder) {
		ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
		try {
			findPrograms(programs, folder);
			System.out.println(programs);

			System.out.println(fidDb);
			
			for (DomainFile program1 : programs) {
				DomainObject domainObject = null;
				domainObject = program1.getDomainObject(this, false, true, TaskMonitor.DUMMY);
				if (!(domainObject instanceof Program)) {
					return;
				}
					
				Program program = (Program) domainObject;
				FunctionManager functionManager = program.getFunctionManager();
				FunctionIterator functions = functionManager.getFunctions(true);
				for (Function function : functions) {
					
					System.out.println(function.getName());
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

			
			FidPopulateResult result = service.createNewLibraryFromPrograms(fidDb,
				currentLibraryName, currentLibraryVersion, currentLibraryVariant, programs, null,
				languageID, null, commonSymbols, TaskMonitor.DUMMY);
			reporter.report(result);
		}
		catch (CancelledException e) {
			isCancelled = true;
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Unexpected memory access exception",
				"Please notify the Ghidra team:", e);
		}
		catch (VersionException e) {
			Msg.showError(this, null, "Version Exception",
				"One of the programs in your domain folder cannot be upgraded: " + e.getMessage());
		}
		catch (IllegalStateException e) {
			Msg.showError(this, null, "Illegal State Exception",
				"Unknown error: " + e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, null, "FidDb IOException", "Please notify the Ghidra team:", e);
		}
	}

	private void generate(int depth, DomainFolder fold) {
		if (depth != 0) {
//			pathelement[MASTER_DEPTH - depth] = fold.getName();
			depth -= 1;
			DomainFolder[] subfold = fold.getFolders();
			for (DomainFolder element : subfold) {
				System.out.println("oui");
				generate(depth, element);
				if (isCancelled) {
					return;
				}
			}
			return;
		}
		//pathelement[MASTER_DEPTH] = fold.getName();
		// Reaching here, we are at library depth in the folder hierarchy
		createLibraryNames();

		monitor.setMessage(
			currentLibraryName + ':' + currentLibraryVersion + ':' + currentLibraryVariant);
		boolean isDuplicate = false;
		if (duplicatemap != null) {
			isDuplicate = detectDups(fold);
		}
		if (!isDuplicate) {
			System.out.println("ouid");

			populateLibrary(fold);
		}
		monitor.incrementProgress(1);
	}

	@Override
	protected void run() throws Exception {
		//pathelement = new String[MASTER_DEPTH + 1];
		service = new FidService();

//		FidFileManager.getInstance().createNewFidDatabase(f);
	//	FidFile fidFile = FidFileManager.getInstance().addUserFidFile(f);

		
		String lang = "x86:LE:64:default";
		languageID = new LanguageID(lang);

		parseSymbols();
		reporter = new MyFidPopulateResultReporter();
		
		
		Project project = state.getProject();
		ProjectData projectData = project.getProjectData();
		rootFolder = projectData.getRootFolder();
		countLibraries(MASTER_DEPTH, rootFolder);
		populateLibrary(rootFolder);
		
		monitor.initialize(totalLibraries);		
	}

}