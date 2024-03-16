//Performs all analysis required to discover vulnerable paths within a binary
//@author DFRWS Participant
//@category DFRWS
//@keybinding
//@menupath
//@toolbar
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.collections4.MultiSet;
import org.apache.commons.collections4.multiset.HashMultiSet;
import ghidra.app.script.GhidraScript;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.app.decompiler.*;

public class MainScript extends GhidraScript {
	
	/**********************************
	 * 
	 * 		Pre-provided code
	 * 
	 **********************************/

	private Set<String> loadStrings(String filepath) {
		List<String> frontendStrings = new ArrayList<>();
		try {
			frontendStrings = Files.readAllLines(Paths.get(filepath));
		} catch(IOException e) {
			e.printStackTrace();
		}
		return frontendStrings.stream().limit(25).collect(Collectors.toSet());
	}
	
	private Set<Function> addr2Fn(Set<Address> frontendAddresses) {
		return frontendAddresses
				.stream()
				.map(addr -> {
					Function fnWithString = this.getCurrentProgram().getFunctionManager().getFunctionContaining(addr);
					if (fnWithString != null) { // We found the function
						return fnWithString;
					}
					
					return null; // Function not found
				})
				.filter(fn -> fn != null)
				.collect(Collectors.toSet());
	}

	Map<String, List<PcodeOpAST>> fnToPcodeCache = new HashMap<>();
	
	private List<PcodeOpAST> fn2Pcode(Function toInspect) {
		if (fnToPcodeCache.containsKey(toInspect.getName())) {
			return fnToPcodeCache.get(toInspect.getName());
		}
		
		DecompileResults res = decompFunction(toInspect);
		List<PcodeOpAST> pcodes = new ArrayList<>();
		if (res == null) {
			return pcodes;
		}
		
		res.getHighFunction().getPcodeOps().forEachRemaining(pcodes::add);
		pcodes.sort((PcodeOpAST a, PcodeOpAST b) -> {
			return a.getSeqnum().getOrder() - b.getSeqnum().getOrder();
		});
		pcodes.sort((PcodeOpAST a, PcodeOpAST b) -> {
			return a.getSeqnum().getTarget().compareTo(b.getSeqnum().getTarget());
		});
		fnToPcodeCache.put(toInspect.getName(), pcodes);
		return pcodes;
	}
	
	private DecompileResults decompFunction(Function toDecompile) {
		DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.toggleJumpLoads(true);
		ifc.toggleParamMeasures(true);
		ifc.toggleCCode(true);
		ifc.setOptions(options);
		ifc.openProgram(this.getCurrentProgram());
		DecompileResults res = ifc.decompileFunction(toDecompile, 1000, null);
		ifc.closeProgram();
		return res;
	}
//	
//	private Set<Function> getAllFunctions() {
//		Set<Function> toInspect = new HashSet<>();
//		getCurrentProgram().getFunctionManager().getFunctions(true).forEachRemaining(toInspect::add);
//		return toInspect;
//	}

	private Set<Address> str2UsageAddr(Set<String> frontendKeys) {
		Set<Address> addressesWithString = new HashSet<>();
		
		for(Data data: DefinedDataIterator.definedStrings(this.getCurrentProgram())) {
			String string = (String) data.getValue();
			if (frontendKeys.contains(string)) { // Is it our frontend key?
				for(Reference refToString: data.getReferenceIteratorTo()) { // All refs to "data"
					Address addrRef = refToString.getFromAddress();
					addressesWithString.add(addrRef);
				}
				
			}
		}
		
		return addressesWithString;
	}

	private Set<Function> getFnsContaining(Set<String> searchStrings) {
		Set<Address> frontendAddresses = str2UsageAddr(searchStrings);
		return addr2Fn(frontendAddresses);
	}
	

	/********************************** 
	 * 
	 * 		Your code starts here
	 * 
	 **********************************/
	
	private Set<PcodeOpAST> sinksOf(Set<String> frontendKeys) {
		Set<PcodeOpAST> pcodeCalls = new HashSet<>();
		Set<Function> fnsToAnalyze = getFnsContaining(frontendKeys);
		
		fnsToAnalyze.forEach(fn -> {
			// Your code here!
			
		});
		
		return pcodeCalls;
	}
	
	private MultiSet<Function> pcall2Fn(Set<PcodeOpAST> sinkCallOperations) {
		List<Function> calls = null; // Your code here!
		return new HashMultiSet<>(calls);
	}
	
	public Set<PcodeOpAST> findSourceSinkPaths(Function toAnalyze, String source, int sourceParam, String sink, int sinkParam) {
		var pcodes = fn2Pcode(toAnalyze);
		Set<Long> tainted = new HashSet<>();
		Set<PcodeOpAST> sinkPCalls = new HashSet<>();
		
		pcodes.forEach(pcode -> {
			// Your code here!
			
		});
		
		return sinkPCalls;
	}

	protected void run() throws Exception {
		/** Task 5 - your code here! */

		
		/** Task 7 - your code here! */

		
		/** Task 8 - your code here! */
		

		/** Task 8.1 - your code here! */
		
		
	}

}
