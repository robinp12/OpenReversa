package openfunctionid;

public class MyItem {
	private String name;
    private String info1;
    private String info2;

    public MyItem(String name, String info1, String info2) {
        this.name = name;
        this.info1 = info1;
        this.info2 = info2;
    }

    public String getName() {
        return name;
    }

    public String getInfo1() {
        return info1;
    }

    public String getInfo2() {
        return info2;
    }
}
