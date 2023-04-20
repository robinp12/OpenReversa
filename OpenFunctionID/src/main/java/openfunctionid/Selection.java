package openfunctionid;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.plugin.FidPlugin;
import ghidra.util.HelpLocation;
import ghidra.util.layout.VerticalLayout;

public class Selection extends DialogComponentProvider{
	
	private ArrayList<String[]> output;
	private List<JCheckBox> checkboxes = new ArrayList<>();

	public Selection(ArrayList<String[]> output) {
		super("Select Files", false);
		
		this.output = new ArrayList<>(output);
		
		addWorkPanel(buildMainPanel());
		addOKButton();
		setOkButtonText("Dismiss");
		setRememberSize(false);
		setPreferredSize(400, 400);
		setHelpLocation(new HelpLocation(FidPlugin.FID_HELP, "chooseactivemenu"));
	}
	
	protected void okCallback() {
		close();
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildCheckboxPanelScroller(), BorderLayout.CENTER);
		panel.add(buildButtonPanel(), BorderLayout.SOUTH);
		return panel;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton allButton = new JButton("Select All");
		JButton noneButton = new JButton("Select None");
		allButton.addActionListener(e -> selectAllCheckboxes(true));
		noneButton.addActionListener(e -> selectAllCheckboxes(false));
		panel.add(allButton);
		panel.add(noneButton);
		return panel;
	}

	private void selectAllCheckboxes(boolean b) {
		for (JCheckBox jCheckBox : checkboxes) {
			jCheckBox.setSelected(b);
		}
	}

	private Component buildCheckboxPanelScroller() {
		JScrollPane scrollPane = new JScrollPane(buildCheckBoxPanel());
		return scrollPane;
	}

	private Component buildCheckBoxPanel() {
	    JPanel panel = new JPanel(new VerticalLayout(5));
	    panel.setOpaque(true);
	    panel.setBackground(Color.WHITE);
	    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	    for (String[] names : output) {
	        JCheckBox checkbox = new JCheckBox(names[0]);
	        checkbox.addMouseListener(new MouseAdapter() {
	            public void mouseClicked(MouseEvent e) {
	                if (e.getClickCount() == 2) {
	                    JOptionPane.showMessageDialog(null, "You double-clicked on " + names[1]);
	                }
	            }
	        });
	        checkboxes.add(checkbox);
	        panel.add(checkbox);
	    }
	    return panel;
	}

}
