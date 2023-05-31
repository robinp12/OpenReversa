package openreversa;

//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.File;
import java.io.IOException;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.exception.VersionException;
import db.DBHandle;
import db.DBRecord;
import db.RecordIterator;
import db.Schema;
import db.Table;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.util.task.TaskMonitorAdapter;

public class CreateNewFidDatabase extends GhidraScript {

    protected void run() throws Exception {

        createFidDb();
    }

    // FROM FidPlugin.java from the Extensions of JAVA

    /**
     * Method to create a new FID database. The user will be prompted to enter a file
     * name for the new database.  They can enter the name with or without the required
     * extension (.fidb).  If they don't, we will add it for them.
     *
     * @throws Exception
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

    public void createFidDb() throws Exception {
        File dbFile = askFile("Create new FidDb file", "Create");
        if (dbFile == null) {
            return;
        }

        if (!dbFile.getName().endsWith(FidFile.FID_PACKED_DATABASE_FILE_EXTENSION)) {
            dbFile = new File(dbFile.getParentFile(), dbFile.getName() + FidFile.FID_PACKED_DATABASE_FILE_EXTENSION);
        }

        try {
            FidFileManager fidFileManager = FidFileManager.getInstance();
            fidFileManager.createNewFidDatabase(dbFile);
            fidFileManager.addUserFidFile(dbFile);
        } catch (DuplicateFileException e) {
            Msg.showError(this, null, "Error creating new FidDb file",
                    "File already exists: " + dbFile.getAbsolutePath());
            FidFileManager.getInstance().addUserFidFile(dbFile);
        } catch (IOException e) {
            Msg.showError(this, null, "Error creating new FidDb file",
                    "Caught IOException creating FidDb file", e);
        }
    }

    private void copyTable(Table oldTable, PackedDBHandle newHandle) throws IOException, CancelledException {
        // Pull out table configuration elements
        String tableName = oldTable.getName();                    // Name
        Schema schema = oldTable.getSchema();                    // Schema
        int[] indexedColumns = oldTable.getIndexedColumns();    // Secondardy indices

        Table newTable = newHandle.createTable(tableName, schema, indexedColumns);    // Create new table
        TaskMonitorAdapter monitor = new TaskMonitorAdapter();
        monitor.setMessage("Copying table: " + tableName);
        monitor.setMaximum(oldTable.getRecordCount());
        monitor.setProgress(0);
        RecordIterator iterator = oldTable.iterator();
        while (iterator.hasNext()) {                                // Iterate through old records
            DBRecord record = iterator.next();
            System.out.println(record.getString(0));
            System.out.println(record.getColumnCount());
            System.out.println(record.getByteValue(0));


            System.out.println(record);

            newTable.putRecord(record);                            // Copy as is into new table
            monitor.checkCanceled();
            monitor.incrementProgress(1);
        }
    }

    protected void test() throws Exception {
        File file = askFile("Select FID database file to repack", "OK");
        PackedDatabase pdb;
        pdb = PackedDatabase.getPackedDatabase(file, false, TaskMonitorAdapter.DUMMY);
        DBHandle handle = pdb.open(TaskMonitorAdapter.DUMMY);
        System.out.println(pdb.getContentType());

        String saveFile_name = askString("Select name for copy", "OK");


        PackedDBHandle newHandle = new PackedDBHandle(pdb.getContentType());


        Table[] tables = handle.getTables();
        for (int i = 0; i < tables.length; ++i) {
            long transactionID = newHandle.startTransaction();
            System.out.println(tables[i]);
            System.out.println(newHandle);

            copyTable(tables[i], newHandle);
            newHandle.endTransaction(transactionID, true);
        }
        if (!saveFile_name.endsWith(FidFile.FID_PACKED_DATABASE_FILE_EXTENSION)) {
            newHandle.saveAs(pdb.getContentType(), file.getParentFile(), saveFile_name + FidFile.FID_PACKED_DATABASE_FILE_EXTENSION, TaskMonitorAdapter.DUMMY);

        } else {
            newHandle.saveAs(pdb.getContentType(), file.getParentFile(), saveFile_name, TaskMonitorAdapter.DUMMY);
        }
        newHandle.close();
    }
}