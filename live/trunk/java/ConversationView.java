import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.Iterator;
import javax.swing.*;
import javax.swing.event.*;

import prefuse.*;
import prefuse.action.*;
import prefuse.action.assignment.ColorAction;
import prefuse.action.filter.GraphDistanceFilter;
import prefuse.action.layout.graph.ForceDirectedLayout;
import prefuse.activity.Activity;
import prefuse.controls.*;
import prefuse.data.*;
import prefuse.data.query.SearchQueryBinding;
import prefuse.data.event.TupleSetListener;
import prefuse.data.search.*;
import prefuse.data.tuple.TupleSet;
import prefuse.render.*;
import prefuse.util.*;
import prefuse.util.force.*;
import prefuse.util.ui.*;
import prefuse.visual.*;


public class ConversationView extends JPrefuseApplet {
    private static final String graph = "graph";
    private static final String nodes = "graph.nodes";
    private static final String edges = "graph.edges";

    public void init()
    {
        UILib.setPlatformLookAndFeel();
        ConversationGraphContainer gc =
            new ConversationGraphContainer(
                getParameter("node"),
                getParameter("module"),
                getParameter("filter"),
                getParameter("start"),
                getParameter("end"),
                getCodeBase());
        JComponent graphview = demo(gc);
        this.getContentPane().add(graphview);
    }

    protected JComponent demo(ConversationGraphContainer gc)
    {
        Graph g = gc.getGraph();
        int bytes = gc.getTotalVolume();

        final Visualization vis = new Visualization();
        VisualGraph vg = vis.addGraph(graph, g);
        vis.setValue(edges, null, VisualItem.INTERACTIVE, Boolean.FALSE);

        TupleSet focusGroup = vis.getGroup(Visualization.FOCUS_ITEMS); 
        focusGroup.addTupleSetListener(new TupleSetListener() {
            public void tupleSetChanged(TupleSet ts, Tuple[] add, Tuple[] rem)
            {
                for ( int i=0; i<rem.length; ++i ) {
                    ((VisualItem)rem[i]).setFixed(false);
                    unsetInterest((VisualItem)rem[i]);
                }
                for ( int i=0; i<add.length; ++i ) {
                    ((VisualItem)add[i]).setFixed(false);
                    ((VisualItem)add[i]).setFixed(true);
                    setInterest((VisualItem)add[i]);
                }
                vis.run("draw");
            }
        });

        // set up the renderers
        DefaultRendererFactory rf = new DefaultRendererFactory();

        LabelRenderer org_r = new LabelRenderer();
        org_r.setRoundedCorner(8, 8);
        rf.setDefaultRenderer(org_r);

        LabelRenderer tx_r = new LabelRenderer();
        tx_r.setRoundedCorner(400, 400);
        rf.add("ingroup('graph.nodes') && [type] != '"+CT.NODE_TYPE_ORG+"'", tx_r);

        MyEdgeRenderer er = new MyEdgeRenderer();
        er.setTotalVolume(bytes);
        rf.setDefaultEdgeRenderer(er);

        vis.setRendererFactory(rf);
        
        // -- set up the actions ----------------------------------------------
        ActionList draw = new ActionList();
        draw.add(new ColorAction(nodes, VisualItem.FILLCOLOR, ColorLib.rgb(200,200,255)));
        draw.add(new ColorAction(nodes, VisualItem.STROKECOLOR, 0));
        draw.add(new ColorAction(nodes, VisualItem.TEXTCOLOR, ColorLib.rgb(0,0,0)));
        draw.add(new ColorAction(edges, VisualItem.FILLCOLOR, ColorLib.gray(200)));
        draw.add(new ColorAction(edges, VisualItem.STROKECOLOR, ColorLib.gray(200)));
        
        ColorAction fill = new ColorAction(nodes, 
                VisualItem.FILLCOLOR, ColorLib.rgb(200,200,255));
        fill.add("_fixed", ColorLib.rgb(255,100,100));
        fill.add("_highlight", ColorLib.rgb(255,200,125));
        
        ForceSimulator fsim = new ForceSimulator(); 
        fsim.addForce(new NBodyForce(-20f, -1f, 0.1f)); // nodes to repel each other
        fsim.addForce(new SpringForce());
        fsim.addForce(new DragForce()); 

        MyLayout fdl = new MyLayout(graph, fsim, false);

        ActionList animate = new ActionList(Activity.INFINITY);
        animate.add(fdl);
        animate.add(fill);
        animate.add(new RepaintAction());

        ItemAction nodeColor = new NodeColorAction(nodes);
        ItemAction textColor = new TextColorAction(nodes);
        ActionList recolor = new ActionList();
        recolor.add(nodeColor);
        recolor.add(textColor);
        vis.putAction("recolor", recolor);
        
        // finally, we register our ActionList with the Visualization.
        // we can later execute our Actions by invoking a method on our
        // Visualization, using the name we've chosen below.
        vis.putAction("draw", draw);
        vis.putAction("layout", animate);
        vis.runAfter("draw", "layout");
        vis.runAfter("layout", "recolor");

        SearchTupleSet search = new PrefixSearchTupleSet();
        vis.addFocusGroup(Visualization.SEARCH_ITEMS, search);
        search.addTupleSetListener(new TupleSetListener() {
            public void tupleSetChanged(TupleSet t, Tuple[] add, Tuple[] rem) {
                for ( int i=0; i<rem.length; ++i ) {
                    ((VisualItem)rem[i]).setFixed(false);
                    unsetInterest((VisualItem)rem[i]);
                }
                for ( int i=0; i<add.length; ++i ) {
                    ((VisualItem)add[i]).setFixed(false);
                    ((VisualItem)add[i]).setFixed(true);
                    setInterest((VisualItem)add[i]);
                }
                vis.run("draw");
            }
        });

        // --------------------------------------------------------------------
        // STEP 4: set up a display to show the visualization
        Display display = new Display(vis);

        SearchQueryBinding sq = new SearchQueryBinding(
                (Table)vis.getGroup(nodes), CT.NODE_FIELD_NAME,
                (SearchTupleSet)vis.getGroup(Visualization.SEARCH_ITEMS));
        JSearchPanel searchp = sq.createSearchPanel();
        searchp.setShowResultCount(true);
        searchp.setBorder(BorderFactory.createEmptyBorder(5,5,4,0));
        searchp.setFont(FontLib.getFont("Tahoma", Font.PLAIN, 11));

        final JFastLabel title = new JFastLabel("                 ");
        title.setPreferredSize(new Dimension(350, 20));
        title.setVerticalAlignment(SwingConstants.BOTTOM);
        title.setBorder(BorderFactory.createEmptyBorder(3,0,0,0));
        title.setFont(FontLib.getFont("Tahoma", Font.PLAIN, 16));

        display.addControlListener(new ControlAdapter() {
            public void itemEntered(VisualItem item, MouseEvent e) {
                if ( item.canGetString(CT.NODE_FIELD_NAME) )
                    title.setText(item.getString(CT.NODE_FIELD_NAME));
            }
            public void itemExited(VisualItem item, MouseEvent e) {
                title.setText(null);
            }
        });

        // main display controls
        display.addControlListener(new FocusControl(1));
        display.addControlListener(new DragControl());
        display.addControlListener(new PanControl());
        display.addControlListener(new ZoomControl());
        display.addControlListener(new WheelZoomControl());
        display.addControlListener(new ZoomToFitControl());
        display.addControlListener(new NeighborHighlightControl());
        
        display.setForeground(Color.GRAY);
        display.setBackground(Color.WHITE);
        
        // --------------------------------------------------------------------        
        // STEP 5: launching the visualization
        
        // create a new JSplitPane to present the interface
        Box box = new Box(BoxLayout.X_AXIS);
        box.add(Box.createHorizontalStrut(10));
        box.add(title);
        box.add(Box.createHorizontalGlue());
        box.add(searchp);
        box.add(Box.createHorizontalStrut(3));

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(display, BorderLayout.CENTER);
        panel.add(box, BorderLayout.SOUTH);

        Color BACKGROUND = Color.WHITE;
        Color FOREGROUND = Color.DARK_GRAY;
        UILib.setColor(panel, BACKGROUND, FOREGROUND);

        // now we run our action list and return
        vis.run("draw");
        return panel;
    }

    protected void setInterest(VisualItem vi)
    {
        setInterest(vi, true);
    }

    protected void unsetInterest(VisualItem vi)
    {
        setInterest(vi, false);
    }

    protected void setInterest(VisualItem vi, boolean isInteresting)
    {
        String value = isInteresting ? CT.EDGE_INTERESTING_YES : CT.EDGE_INTERESTING_NO;
        if (! isInteresting)
            vi.setFixed(false);

        /*
         * if node is org, its transmitters also are (un)interesting
         */
        NodeItem ni = (NodeItem) vi;
        if (ni.getString(CT.NODE_FIELD_TYPE).equals(CT.NODE_TYPE_ORG)) {
            Iterator it = ni.outEdges();
            while (it.hasNext()) {
                EdgeItem ei = (EdgeItem)it.next();
                NodeItem ni2 = ei.getTargetItem();
                if (ni2.getString(CT.NODE_FIELD_TYPE).equals(CT.NODE_TYPE_TRANSMITTER))
                    setInterest(ni2, isInteresting);
            }
        }

        /*
         * All outgoing edges share the node's interestingness.
         */
        Iterator it = ni.outEdges();
        while (it.hasNext()) {
            EdgeItem ei = (EdgeItem)it.next();
            ei.setString(CT.EDGE_FIELD_INTERESTING, value);
        }
    }

    public static class NodeColorAction extends ColorAction {
        public NodeColorAction(String group) {
            super(group, VisualItem.FILLCOLOR, ColorLib.rgba(255,255,255,0));
            add("_hover", ColorLib.gray(220,230));
            add("ingroup('_search_')", ColorLib.rgb(255,190,190));
        }
    }

    public static class TextColorAction extends ColorAction {
        public TextColorAction(String group) {
            super(group, VisualItem.TEXTCOLOR, ColorLib.gray(0));
            add("_hover", ColorLib.rgb(255,0,0));
        }
    }
}

