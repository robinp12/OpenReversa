package openfunctionid;

import java.awt.BorderLayout;
import java.awt.Component;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.ListCellRenderer;

public class JCheckBoxListCellRenderer<E> extends JPanel implements ListCellRenderer<E> {
    private final JCheckBox checkBox;
    private final JLabel label;

    public JCheckBoxListCellRenderer() {
        setLayout(new BorderLayout());
        checkBox = new JCheckBox();
        label = new JLabel();
        add(checkBox, BorderLayout.WEST);
        add(label, BorderLayout.CENTER);
    }

    @Override
    public Component getListCellRendererComponent(JList<? extends E> list, E value, int index, boolean isSelected, boolean cellHasFocus) {
        checkBox.setSelected(isSelected);
        setBackground(list.getBackground());
        setForeground(list.getForeground());
        label.setText(value == null ? "" : value.toString()); // Render the text of the list item
        return this;
    }
}