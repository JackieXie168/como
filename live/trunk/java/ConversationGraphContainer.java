import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.net.URL;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
//import java.util.Array;
import java.lang.reflect.Array;

import prefuse.data.Edge;
import prefuse.data.Graph;
import prefuse.data.Node;
import prefuse.data.Schema;


/**
 * Loads a Graph from input files
 *
 * @version 0.1
 * @author <a href="mailto:jsanjuas@ac.upc.edu">Josep Sanjuas</a>
 */
public class ConversationGraphContainer {
    protected Graph m_g;
    protected HashMap m_rtx2node;
    protected HashMap m_org2node;
    protected int m_totalVolume;
    protected LinkedList m_record_display_queue;
    protected LinkedList m_record_exp_queue;

    // Parameters to get the graph data
    protected String m_node;
    protected String m_module;
    protected String m_filter;
    protected String m_start;
    protected String m_end;

    public ConversationGraphContainer(String node, String module, String filter,
                                        String start, String end, URL codeBase)
    {
        m_node = node;
        m_module = module;
        m_filter = filter;
        m_start = start;
        m_end = end;

        m_g = new Graph(true);

        Schema ns = new Schema();
        ns.addColumn(CT.NODE_FIELD_LABEL, String.class, "");
        ns.addColumn(CT.NODE_FIELD_NAME, String.class, "");
        ns.addColumn(CT.NODE_FIELD_TYPE, String.class, "");
        m_g.getNodeTable().addColumns(ns);

        Schema es = new Schema();
        es.addColumn(CT.EDGE_FIELD_TYPE, String.class, "");
        es.addColumn(CT.EDGE_FIELD_VOLUME, String.class, "");
        es.addColumn(CT.EDGE_FIELD_INTERESTING, String.class, "no");
        m_g.getEdgeTable().addColumns(es);

        m_rtx2node = new HashMap();
        m_org2node = new HashMap();
        m_record_exp_queue = new LinkedList();
        m_record_display_queue = new LinkedList();
        m_totalVolume = 0;

        updateGraph(codeBase);
    }

    public Graph getGraph()
    {
        return m_g;
    }

    public int getTotalVolume()
    {
        return m_totalVolume;
    }

    protected Node addOrganization(Graph g, String name)
    {
        Node n = g.addNode();
        n.setString(CT.NODE_FIELD_LABEL, name);
        n.setString(CT.NODE_FIELD_NAME, name);
        n.setString(CT.NODE_FIELD_TYPE, CT.NODE_TYPE_ORG);
        m_org2node.put(name, n);
        System.out.println("Adding node for organization " + name);

        /* 
         * Add edges to the rest of ISPs. This will
         * help make them stay distributed in a circle
         *
         * XXX expensive, norgs * (norgs - 1) / 2 edges
         */
        Iterator it = m_org2node.keySet().iterator();
        while (it.hasNext()) {
            String s = (String) it.next();
            Node n2 = (Node) m_org2node.get(s);
            addEdge(g, n, n2, CT.EDGE_TYPE_ORG_TO_ORG);
            addEdge(g, n2, n, CT.EDGE_TYPE_ORG_TO_ORG);
        }

        return n;
    }

    protected Node addTransmitter(Graph g, Node org_node, String name)
    {
        Node n = g.addNode();
        System.out.println("adding node for transmitter "+name);
        n.setString(CT.NODE_FIELD_LABEL, "   "); //rtx nodes will have no label
        n.setString(CT.NODE_FIELD_NAME, name);
        n.setString(CT.NODE_FIELD_TYPE, CT.NODE_TYPE_TRANSMITTER);
        m_rtx2node.put(name, n);

        addEdge(m_g, org_node, n, CT.EDGE_TYPE_ORG_TO_TRANSMITTER);

        return n;
    }

    protected Edge addEdge(Graph g, Node n1, Node n2, String type)
    {
        Edge e = g.addEdge(n1, n2);
        e.setString(CT.EDGE_FIELD_TYPE, type);
        return e;
    }

    public void updateGraph(URL codeBase)
    {
        /*
         * load MAC and ISP information
         */
        String args = "?module=" + m_module;
        args += "&node=" + m_node;
        args += "&filter=" + m_filter;
        args += "&start=" + m_start;
        args += "&end=" + m_end;
        args += "&format=conversation_graph";
        System.out.println("query string is "+args);

        int activity[] = {};
        String[] orgs = {};
        String[] rtxs = {};
        int[][] traffic = {};

        try {
            URL datafile = new URL(codeBase.toString() + "getdata.php" + args);
            BufferedReader r = new BufferedReader(
                new InputStreamReader(datafile.openStream()));
            String l;
            boolean firstLine = true;
            int idx = 0;
            int elem = -1;
            while ((l = r.readLine()) != null) {
                System.out.println("parsing line "+l);
                String[] split = l.split(",");
                String org = split[0];
                String rtx = split[1];
                if (firstLine) {
                    firstLine = false;
                    elem = split.length - 2;
                    orgs = new String[elem];
                    rtxs = new String[elem];
                    activity = new int[elem];
                    traffic = new int[elem][elem];
                }
                orgs[idx] = org;
                rtxs[idx] = rtx;
                for (int i = 0; i < elem; i++) {
                    traffic[idx][i] = (new Integer(split[i+2])).intValue();
                    if (traffic[idx][i] != 0) { // record active organisations
                        activity[idx] = 1;
                        activity[i] = 1;
                    }
                }
                idx++;
            }

            // 1 - add active organizations and its active transmitters
            for (int i = 0; i < elem; i++) {
                String org = orgs[i];
                String rtx = rtxs[i];
                if (activity[i] != 1)
                    continue;
                Node org_n;
                if (! m_org2node.containsKey(org))
                    org_n = addOrganization(m_g, org);
                else
                    org_n = (Node) m_org2node.get(org);
                addTransmitter(m_g, org_n, rtx);
            }

            // 2 - add edges
            for (int i = 0; i < elem; i++) {
                String rtx1 = rtxs[i];
                if (activity[i] != 1)
                    continue;
                for (int j = 0; j < elem; j++) {
                    if (activity[j] != 1 || traffic[i][j] == 0)
                        continue;
                    traffic[i][j] = 1;
                    String rtx2 = rtxs[j];
                    System.out.println("Let's add "+rtx1+" -> "+rtx2+" (volume="+traffic[i][j]+")");
                    Edge e = addEdge(m_g,
                                     (Node) m_rtx2node.get(rtx1),
                                     (Node) m_rtx2node.get(rtx2),
                                     CT.EDGE_TYPE_TRANSMITTER_TO_TRANSMITTER);
                    e.setString(CT.EDGE_FIELD_VOLUME, new Integer(traffic[i][j]).toString());
                    m_totalVolume += traffic[i][j];
                }
            }
            //throw new Exception("asdf");
        } catch ( Exception e ) {
            System.out.println("Error reading input file");
            System.out.println(e.toString());
            System.out.println("Stack trace follows:");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
