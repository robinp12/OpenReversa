package openfunctionid;

//TODO write a description for this script
//@author Zina Rasoamanana 
//@category test
//@keybinding 
//@menupath 
//@toolbar test.png


import java.io.File;
import java.io.IOException;
//Headless
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.hash.FunctionBodyFunctionExtentGenerator;
import ghidra.feature.fid.plugin.IngestTask;
import ghidra.feature.fid.service.DefaultFidPopulateResultReporter;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidPopulateResultReporter;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.service.Location;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

public class CustomPopulate extends HeadlessScript {
  	
    	public void populate() throws CancelledException, VersionException, IOException, MemoryAccessException{

    	FidFileManager fidFileManager = FidFileManager.getInstance();

		List<FidFile> allKnownFidFiles = fidFileManager.getFidFiles();
		ArrayList<String> dbfiles = new ArrayList<>();
		HashMap<String, FidFile> fidMap = new HashMap<>();
		for (FidFile fidFile : allKnownFidFiles) {
			if (!fidFile.isInstalled()) {
				fidMap.put(fidFile.getName(), fidFile);
				dbfiles.add(fidFile.getName());
			}
		}
		String[] nameArray = new String[dbfiles.size()];
		dbfiles.toArray(nameArray);
		String askChoice = askString("AddFunction", "Choose FID database: ", nameArray[0]);

		FidFile fidFile = fidMap.get(askChoice);
		if (fidFile == null) {
			fidFile = fidFileManager.addUserFidFile(new File(askChoice));
		}
    	
		FidDB fidDB = fidFile.getFidDB(false);
		List<LibraryRecord> allLibraries = fidDB.getAllLibraries();
		LibraryRecord libraryRecord = allLibraries.get(allLibraries.size()-1);//TODO
		System.out.println(libraryRecord);

		allLibraries.add(libraryRecord);
		
		String libraryFamilyName = askString("libraryFamilyName : ", "OK");
		String libraryVersion = askString("version : ", "OK");
		String libraryVariant = askString("variant : ", "OK");
		
		//get folder of project
		//Project project = state.getProject();
		//ProjectData pd = project.getProjectData();
		//DomainFolder folder = pd.getFolder("/");//change to the right folder
		DomainFolder root = getProjectRootFolder();
		
		String languageFilter = askString("languageFilter(x86:LE:64:default) : ", "OK");
		File commonSymbolsFile = null; //TODO
		
		FidService fidService = new FidService();
		//TODO NEED TO UNDERSTAND fidService (where is program function)

		System.out.println("fidFile");
		System.out.println(fidFile);
		System.out.println("libraryRecord");
		System.out.println(libraryRecord);
		System.out.println("root");
		System.out.println(root);
		System.out.println("libraryFamilyName");
		System.out.println(libraryFamilyName);
		System.out.println("libraryVersion");
		System.out.println(libraryVersion);
		System.out.println("libraryVariant");
		System.out.println(libraryVariant);
		System.out.println("languageFilter");
		System.out.println(languageFilter);
		System.out.println("commonSymbolsFile");
		System.out.println(commonSymbolsFile);
		System.out.println("fidService");
		
		System.out.println(fidService.hashCode());


		Task task = new IngestTask("Populate Library Task", fidFile, libraryRecord, root,
			libraryFamilyName, libraryVersion, libraryVariant, "x86:LE:64:default", commonSymbolsFile,
			fidService, new MyFidPopulateResultReporter());
		
		
		//GhidraTool test = new GhidraTool(project,"functionid");
		//PluginTool temp = launchTool("functionID");
		//System.out.println(temp);
		//AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(currentProgram);
		//aam.getAnalysisTool().execute(task);
		//state.getTool().execute(task);
		TaskMonitorAdapter monitor = new TaskMonitorAdapter();

		task.run(monitor);
		
    }

		@Override
		protected void run() throws Exception {
			populate();
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
		TreeSet<String> symbols = new TreeSet<>();
		for (Location location : result.getUnresolvedSymbols()) {
			symbols.add(location.getFunctionName());
		}
		for (String symbol : symbols) {
			outputLine("    " + symbol);
		}
	}
	
	protected void outputLine(String line) {
		System.out.println(line);
	}

}
