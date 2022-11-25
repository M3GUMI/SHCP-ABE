package test;

import abe.access_structure.AccessStructure;
import abe.access_structure.matrix.LSSSMatrix;
import abe.entities.aa.AttributeAuthority;
import abe.entities.dos.DataOwner;
import abe.entities.du.AssignedAttribute;
import abe.entities.du.DataUser;
import abe.entities.tsp.TeleServiceProvider;
import abe.keys.ElementTest;
import abe.keys.PublicKey;
import abe.keys.res1.Response1;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import javafx.scene.chart.XYChart;
import org.junit.Test;
import org.w3c.dom.Attr;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ABETest {
    Pairing bp = PairingFactory.getPairing("src/resources/a.properties");
    Field G1 = bp.getG1();
    Field Zr = bp.getZr();
    Field GT = bp.getGT();

    public static void main(String[] args) throws Exception{
        ABETest abeTest = new ABETest();
        System.out.println("-------setupTimeTest-------");
        abeTest.setupTimeTest();
        System.out.println("-------keyGenTimeTest-------");
        abeTest.keyGenTimeTest();
        System.out.println("-------encTimeTest-------");
        abeTest.encTimeTest();
        System.out.println("-------queryGenTimeTest-------");
        abeTest.queryGenTimeTest();
        System.out.println("-------nameMatchTimeTest-------");
        abeTest.nameMatchTimeTest();
        System.out.println("-------policyDecTimeTest-------");
        abeTest.policyDecTimeTest();
        System.out.println("-------spanMatchTimeTest-------");
        abeTest.spanMatchTimeTest();
        System.out.println("-------spanDecTimeTest-------");
        abeTest.spanDecTimeTest();
    }

    @Test
    public void setupTimeTest(){
        long[] times = new long[]{0,0,0,0,0};
        for (int i = 0; i < 100; i++) {
            for (int j = 1; j < 6; j++) {
                times[j-1] = times[j-1] + PublicKeyTest.setupTime("src/resources/setup/attributesets" + j + ".txt");
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("SetupTime[attributeSet.size=" + i*20 + "]:" + times[i]/100+"ms");
        }
    }

    @Test
    public void keyGenTimeTest() throws IOException {
        AttributeAuthority.setup();

        File file = new File("src/resources/keyGen/attributes.txt");

        InputStreamReader isr = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8);
        BufferedReader reader = new BufferedReader(isr);
        String tempString = null;
        AttributeAuthority.setup();
        long[] times = new long[]{0,0,0,0,0};

        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 100; j++) {
                tempString = reader.readLine();
                String[] assignedAttributeArray = tempString.split(",");
                List<AssignedAttribute> assignedAttributeList = new ArrayList<>();
                for (int l = 0; l < assignedAttributeArray.length; l++) {
                    assignedAttributeList.add(new AssignedAttribute(assignedAttributeArray[i]));
                }
                times[i] = times[i] + AttributeAuthority.keyGenTime(assignedAttributeList);
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("KeyGenTime[attributes.num=" + i*5 + "]:" + times[i]/100+"ms");
        }

        reader.close();
        isr.close();
    }

    @Test
    public void encTimeTest() throws Exception{
        AttributeAuthority.setup();
        DataOwner DO = new DataOwner();
        File file = new File("src/resources/enc/policies");
        FileInputStream fis = new FileInputStream(file);
        InputStreamReader isr = new InputStreamReader(fis);
        BufferedReader reader = new BufferedReader(isr);
        String tempPolicy = null;

        long[] times = new long[]{0,0,0,0,0};
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 10; j++) {
                String policy = reader.readLine();
                long time = DO.EncTime(policy, "MEGUMI");
                times[i] = times[i] + time;
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("EncTime[policy.size=" + (i+1)*4 + "]:" + times[i]/10+"ms");
        }
    }

    @Test
    public void queryGenTimeTest() throws Exception{
        AttributeAuthority.setup();
        DataOwner DO = new DataOwner();
        File file2 = new File("src/resources/keyGen/attributes_p.txt");
        FileInputStream fis2 = new FileInputStream(file2);
        InputStreamReader isr2 = new InputStreamReader(fis2);
        BufferedReader reader2 = new BufferedReader(isr2);

        long[] times = new long[]{0,0,0,0,0};
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 10; j++) {
                String attributes = reader2.readLine();
                String[] attributeArray = attributes.split(",");
                List<AssignedAttribute> assignedAttributes = new ArrayList<>();
                for (int k = 0; k < attributeArray.length; k++) {
                    assignedAttributes.add(new AssignedAttribute(attributeArray[k]));
                }
                DataUser DU = new DataUser(assignedAttributes);
                long time = DU.queryGenTime();
                times[i] = times[i] + time;
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("QueryGenTime[attribute.num=" + (i+1)*4 + "]:" + times[i]/10+"ms");
        }
        reader2.close();
        isr2.close();
        fis2.close();
    }

    @Test
    public void nameMatchTimeTest() throws Exception{
        AttributeAuthority.setup();
        DataOwner DO = new DataOwner();

        File file1 = new File("src/resources/enc/policies");
        FileInputStream fis1 = new FileInputStream(file1);
        InputStreamReader isr1 = new InputStreamReader(fis1);
        BufferedReader reader1 = new BufferedReader(isr1);
        File file2 = new File("src/resources/keyGen/attributes_p.txt");
        FileInputStream fis2 = new FileInputStream(file2);
        InputStreamReader isr2 = new InputStreamReader(fis2);
        BufferedReader reader2 = new BufferedReader(isr2);

        long[] times = new long[]{0,0,0,0,0};
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 10; j++) {
                String policy = reader1.readLine();
                String attributes = reader2.readLine();
                DO.Enc(policy, "MEGUMI");

                String[] attributeArray = attributes.split(",");
                List<AssignedAttribute> assignedAttributes = new ArrayList<>();
                for (int k = 0; k < attributeArray.length; k++) {
                    assignedAttributes.add(new AssignedAttribute(attributeArray[k]));
                }
                DataUser DU = new DataUser(assignedAttributes);
                long time = DU.nameMatchTime();
                times[i] = times[i] + time;
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("NameMatchTime[attribute.num=" + (i+1)*4 + "]:" + times[i]/10+"ms");
        }
    }

    @Test
    public void policyDecTimeTest() throws Exception{
        AttributeAuthority.setup();
        DataOwner DO = new DataOwner();

        File file1 = new File("src/resources/enc/policies");
        FileInputStream fis1 = new FileInputStream(file1);
        InputStreamReader isr1 = new InputStreamReader(fis1);
        BufferedReader reader1 = new BufferedReader(isr1);
        File file2 = new File("src/resources/keyGen/attributes_p.txt");
        FileInputStream fis2 = new FileInputStream(file2);
        InputStreamReader isr2 = new InputStreamReader(fis2);
        BufferedReader reader2 = new BufferedReader(isr2);

        long[] times = new long[]{0,0,0,0,0};
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 10; j++) {
                String policy = reader1.readLine();
                String attributes = reader2.readLine();
                DO.Enc(policy, "MEGUMI");

                String[] attributeArray = attributes.split(",");
                List<AssignedAttribute> assignedAttributes = new ArrayList<>();
                for (int k = 0; k < attributeArray.length; k++) {
                    assignedAttributes.add(new AssignedAttribute(attributeArray[k]));
                }
                DataUser DU = new DataUser(assignedAttributes);
                Response1 res1 = DU.query1();
                long time = DU.policyDecTime(res1);
                times[i] = times[i] + time;
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("PolicyDecTime[policy.size=" + (i+1)*4 + "]:" + times[i]/10+"ms");
        }
    }

    @Test
    public void spanMatchTimeTest() throws Exception{
        AttributeAuthority.setup();
        DataOwner DO = new DataOwner();

        File file1 = new File("src/resources/enc/policies");
        FileInputStream fis1 = new FileInputStream(file1);
        InputStreamReader isr1 = new InputStreamReader(fis1);
        BufferedReader reader1 = new BufferedReader(isr1);
        File file2 = new File("src/resources/keyGen/attributes_p.txt");
        FileInputStream fis2 = new FileInputStream(file2);
        InputStreamReader isr2 = new InputStreamReader(fis2);
        BufferedReader reader2 = new BufferedReader(isr2);

        long[] times = new long[]{0,0,0,0,0};
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 10; j++) {
                String policy = reader1.readLine();
                String attributes = reader2.readLine();
                DO.Enc(policy, "MEGUMI");

                String[] attributeArray = attributes.split(",");
                List<AssignedAttribute> assignedAttributes = new ArrayList<>();
                for (int k = 0; k < attributeArray.length; k++) {
                    assignedAttributes.add(new AssignedAttribute(attributeArray[k]));
                }
                DataUser DU = new DataUser(assignedAttributes);
                Response1 res1 = DU.query1();
                long time = DU.spanMatchTime(res1);
                times[i] = times[i] + time;
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("SpanMatchTime[attribute.num=" + (i+1)*4 + "]:" + times[i]/10+"ms");
        }
    }

    @Test
    public void spanDecTimeTest() throws Exception{
        AttributeAuthority.setup();
        DataOwner DO = new DataOwner();

        File file1 = new File("src/resources/enc/policies");
        FileInputStream fis1 = new FileInputStream(file1);
        InputStreamReader isr1 = new InputStreamReader(fis1);
        BufferedReader reader1 = new BufferedReader(isr1);
        File file2 = new File("src/resources/keyGen/attributes_p.txt");
        FileInputStream fis2 = new FileInputStream(file2);
        InputStreamReader isr2 = new InputStreamReader(fis2);
        BufferedReader reader2 = new BufferedReader(isr2);

        long[] times = new long[]{0,0,0,0,0};
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 10; j++) {
                String policy = reader1.readLine();
                String attributes = reader2.readLine();
                DO.Enc(policy, "MEGUMI");

                String[] attributeArray = attributes.split(",");
                List<AssignedAttribute> assignedAttributes = new ArrayList<>();
                for (int k = 0; k < attributeArray.length; k++) {
                    assignedAttributes.add(new AssignedAttribute(attributeArray[k]));
                }
                DataUser DU = new DataUser(assignedAttributes);
                Response1 res1 = DU.query1();
                long time = DU.spanDecTime(res1);
                times[i] = times[i] + time;
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("SpanDecTime[attribute.num=" + (i+1)*4 + "]:" + times[i]/10+"ms");
        }
    }

    @Test
    public void policyIO() throws Exception{
        File file1 = new File("src/resources/enc/policies");
        OutputStreamWriter osw1 = new FileWriter(file1);
        BufferedWriter bos1 = new BufferedWriter(osw1);

        File file2 = new File("src/resources/keyGen/attributes_p.txt");
        OutputStreamWriter osw2 = new FileWriter(file2);
        BufferedWriter bos2 = new BufferedWriter(osw2);
        Random random = new Random();

        for (int i = 1; i < 6; i++) {
            for (int j = 0; j < 10; j++) {
                Map<String, String> a = new HashMap<>();
                for (int k = 0; k < 4*i-1; k++) {
                    String user = null;
                    while (a.containsKey(user = "user" + random.nextInt(100)));
                    bos1.append(user + " and ");
                    bos2.append(user + ",");
                    a.put(user, user);
                }
                String user = null;
                while (a.containsKey(user = "user" + random.nextInt(100)));
                bos1.append(user + "\n");
                bos2.append(user + "\n");
            }
        }

        bos1.close();
        osw1.close();
        bos2.close();
        osw2.close();
    }

    @Test
    public void structureTest(){
        AttributeAuthority.setup();
        long startTimeAll = System.currentTimeMillis();
        long startTime = System.currentTimeMillis();
        DataOwner DO = new DataOwner();
        DO.Enc("user and Teacher and Student", "MEGUMI");
        long endTime = System.currentTimeMillis();
        System.out.println("Enc:"+(endTime-startTime));

        List<AssignedAttribute> assignedAttributes = new ArrayList<>();
        assignedAttributes.add(new AssignedAttribute("Teacher"));
        assignedAttributes.add(new AssignedAttribute("Student"));
        assignedAttributes.add(new AssignedAttribute("user"));
        assignedAttributes.add(new AssignedAttribute("user0"));
        assignedAttributes.add(new AssignedAttribute("user1"));
        assignedAttributes.add(new AssignedAttribute("user2"));

        startTime = System.currentTimeMillis();
        DataUser DU = new DataUser(assignedAttributes);
        endTime = System.currentTimeMillis();
        System.out.println("KeyGen:"+(endTime-startTime));
        Response1 res1 = DU.query1();

        byte[] plaintext = DU.query2(res1);
        System.out.println(new String(plaintext));

        long endTimeAll = System.currentTimeMillis();
        System.out.println(endTimeAll-startTimeAll);
    }
}
