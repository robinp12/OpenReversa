//Search on internet a man page for the current selected function
//@author Cyprien Janssens - Zina Rasoamanana
//@category Lookup
//@keybinding ctrl 5
//@menupath File.Run.Lookup
//@toolbar icon_lookup.png

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;

public class HomeScript_Lookup extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentSelection != null) {
			println("Selection : "+currentSelection.toString());
		}
		if(currentHighlight != null ) {
			println("Highlight : "+ currentHighlight.toString());
		}
		if (currentProgram != null) {
			println("Address : "+ currentAddress.toString());
			ghidra.program.model.listing.Function funct = currentProgram.getFunctionManager().getFunctionAt(currentAddress);
			//Checks if a function is selected
			if(funct == null) {
				println("No function selected");
				return;
			}
			//Print information about the function
			println("Function selected :\n \t Name : \t\t\t\t"+funct.getName()
			+ "\n \t CallingConventionName : \t \t"+funct.getCallingConventionName()
			+ "\n \t DefaultCallingConventionName : \t"+funct.getDefaultCallingConventionName()
			+ "\n \t PrototypeString : \t\t\t"+funct.getPrototypeString(true, true));
			
			//Call man
			if(askMan(funct.getName())) {
				//Open the browser
				//Site #1
				String urlToCall = "http://man.he.net/?topic="+funct.getName()+"&section=all";
				//Site #2
				urlToCall = "https://man.cx/"+funct.getName();
				java.awt.Desktop.getDesktop().browse(new java.net.URI(urlToCall));
			} else {
				println("The function \""+funct.getName()+"\" selected does not occur in the linux man pages");
			}
		} else {
			println("currentProgram is null ! This plugin cannot find the functions");
		}
	}
	
	/**
	 * 
	 * @param function is the name of the function to lookup with man
	 * @return true if man returns something, false if not
	 * @throws Exception
	 */
	private boolean askMan(String function) throws Exception {
	    InputStream in    = new ProcessBuilder().command("man",function).start().getInputStream();
	    BufferedReader br = new BufferedReader( new InputStreamReader(in));
		String lines = br.lines().collect(Collectors.joining(System.lineSeparator()));
	    long count = lines.split(System.lineSeparator()).length;

		return count>1;
	}
}
