package openreversa;

//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.IOException;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class ChooseFidDatabase extends GhidraScript {

    protected void run() throws Exception {

    }
    
    //select the FiDb to populate
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
}