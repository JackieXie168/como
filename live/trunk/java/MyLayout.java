// TODO override run() and inherit from ForceDirectedLayout
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.Iterator;

import prefuse.action.layout.Layout;
import prefuse.data.Graph;
import prefuse.data.Schema;
import prefuse.data.tuple.TupleSet;
import prefuse.util.PrefuseLib;
import prefuse.util.force.DragForce;
import prefuse.util.force.ForceItem;
import prefuse.util.force.ForceSimulator;
import prefuse.util.force.NBodyForce;
import prefuse.util.force.SpringForce;
import prefuse.visual.EdgeItem;
import prefuse.visual.NodeItem;
import prefuse.visual.VisualItem;

public class MyLayout extends Layout {
    
    private ForceSimulator m_fsim;
    private long m_lasttime = -1L;
    private long m_maxstep = 50L;
    private boolean m_runonce;
    private int m_iterations = 100;
    private boolean m_enforceBounds;
    
    protected transient VisualItem referrer;
    
    protected String m_nodeGroup;
    protected String m_edgeGroup;
    
    public MyLayout(String graph)
    {
        this(graph, false, false);
    }

    public MyLayout(String group, boolean enforceBounds)
    {
        this(group, enforceBounds, false);
    }
    
    public MyLayout(String group,
            boolean enforceBounds, boolean runonce)
    {
        super(group);
        m_nodeGroup = PrefuseLib.getGroupName(group, Graph.NODES);
        m_edgeGroup = PrefuseLib.getGroupName(group, Graph.EDGES);
        
        m_enforceBounds = enforceBounds;
        m_runonce = runonce;
        m_fsim = new ForceSimulator();
        m_fsim.addForce(new NBodyForce());
        m_fsim.addForce(new SpringForce());
        m_fsim.addForce(new DragForce());
    }
    
    public MyLayout(String group,
            ForceSimulator fsim, boolean enforceBounds) {
        this(group, fsim, enforceBounds, false);
    }
    
    public MyLayout(String group, ForceSimulator fsim,
            boolean enforceBounds, boolean runonce)
    {
        super(group);
        m_nodeGroup = PrefuseLib.getGroupName(group, Graph.NODES);
        m_edgeGroup = PrefuseLib.getGroupName(group, Graph.EDGES);
        
        m_enforceBounds = enforceBounds;
        m_runonce = runonce;
        m_fsim = fsim;
    }
    
    // ------------------------------------------------------------------------
    
    public long getMaxTimeStep() {
        return m_maxstep;
    }

    public void setMaxTimeStep(long maxstep) {
        this.m_maxstep = maxstep;
    }
    
    public ForceSimulator getForceSimulator() {
        return m_fsim;
    }
    
    public void setForceSimulator(ForceSimulator fsim) {
        m_fsim = fsim;
    }
    
    public int getIterations() {
        return m_iterations;
    }

    public void setIterations(int iter) {
        if ( iter < 1 )
            throw new IllegalArgumentException(
                    "Iterations must be a positive number!");
        m_iterations = iter;
    }
    
    public void setDataGroups(String nodeGroup, String edgeGroup) {
        m_nodeGroup = nodeGroup;
        m_edgeGroup = edgeGroup;
    }
    
    // ------------------------------------------------------------------------
    
    /**
     * @see prefuse.action.Action#run(double)
     */
    public void run(double frac) {
        // get timestep
        if ( m_lasttime == -1 )
            m_lasttime = System.currentTimeMillis()-20;
        long time = System.currentTimeMillis();
        long timestep = Math.min(m_maxstep, time - m_lasttime);
        m_lasttime = time;
            
        // run force simulator
        m_fsim.clear();
        initSimulator(m_fsim);
        m_fsim.runSimulator(timestep);
        updateNodePositions();
        if ( frac == 1.0 )
            reset();
    }

    private void updateNodePositions() {
        Rectangle2D bounds = getLayoutBounds();
        double x1=0, x2=0, y1=0, y2=0;
        if ( bounds != null ) {
            x1 = bounds.getMinX(); y1 = bounds.getMinY();
            x2 = bounds.getMaxX(); y2 = bounds.getMaxY();
        }
        
        // update positions
        Iterator iter = m_vis.visibleItems(m_nodeGroup);
        int ic = 0;
        while ( iter.hasNext() ) {
            VisualItem item = (VisualItem)iter.next();
            ForceItem fitem = (ForceItem)item.get(FORCEITEM);

            if ( Double.isNaN(item.getX()) ) {
                setX(item, referrer, 0.0);
                setY(item, referrer, 0.0);
            }
            if (item.isFixed())
                continue;

            double x = fitem.location[0];
            double y = fitem.location[1];
            String t = item.getString(CT.NODE_FIELD_TYPE);

            if (t.equals(CT.NODE_TYPE_ORG)) {
                double min_radius = 200;
                double max_radius = 200;
                double len = Math.sqrt(x * x + y * y);
                if (len > max_radius) {
                    x = x * max_radius / len;
                    y = y * max_radius / len;
                } else if (len < min_radius) {
                    x = x * min_radius / len;
                    y = y * min_radius / len;
                }
            } else if (t.equals(CT.NODE_TYPE_TRANSMITTER)) {
                // locate (x, y) for trasmitters's org node
                double parent_x = 0, parent_y = 0;
                boolean found = false;

                NodeItem n = (NodeItem) item;
                Iterator it = n.inEdges();
                while (it.hasNext()) {
                    EdgeItem e = (EdgeItem) it.next();
                    NodeItem origin = (NodeItem) e.getSourceNode();
                    if (origin.getString(CT.NODE_FIELD_TYPE).equals(CT.NODE_TYPE_ORG)) {
                        parent_x = origin.getX();
                        parent_y = origin.getY();
                        found = true;
                        break;
                    }
                }
                /*if (! found)
                    throw new Exception("Malformed graph");*/

                // force transmitter to be on a circumference around org node
                double min_radius = 30;
                double max_radius = 60;
                double tx = x - parent_x;
                double ty = y - parent_y;
                double len = Math.sqrt(tx * tx + ty * ty);
                if (len > max_radius) {
                    tx = tx * max_radius / len;
                    ty = ty * max_radius / len;
                } else if (len < min_radius) {
                    tx = tx * min_radius / len;
                    ty = ty * min_radius / len;
                }
                x = tx + parent_x;
                y = ty + parent_y;
            }

            // set the actual position
            setX(item, referrer, x);
            setY(item, referrer, y);
        }
    }
    
    /**
     * Reset the force simulation state for all nodes processed
     * by this layout.
     */
    public void reset() {
        Iterator iter = m_vis.visibleItems(m_nodeGroup);
        while ( iter.hasNext() ) {
            VisualItem item = (VisualItem)iter.next();
            ForceItem fitem = (ForceItem)item.get(FORCEITEM);
            if ( fitem != null ) {
                fitem.location[0] = (float)item.getEndX();
                fitem.location[1] = (float)item.getEndY();
                fitem.force[0]    = fitem.force[1]    = 0;
                fitem.velocity[0] = fitem.velocity[1] = 0;
            }
        }
        m_lasttime = -1L;
    }
    
    /**
     * Loads the simulator with all relevant force items and springs.
     * @param fsim the force simulator driving this layout
     */
    protected void initSimulator(ForceSimulator fsim) {     
        // make sure we have force items to work with
        TupleSet ts = m_vis.getGroup(m_nodeGroup);
        if ( ts == null ) return;
        try {
            ts.addColumns(FORCEITEM_SCHEMA);
        } catch ( IllegalArgumentException iae ) { /* ignored */ }
        
        float startX = (referrer == null ? 0f : (float)referrer.getX());
        float startY = (referrer == null ? 0f : (float)referrer.getY());
        startX = Float.isNaN(startX) ? 0f : startX;
        startY = Float.isNaN(startY) ? 0f : startY;
       
        Iterator iter = m_vis.visibleItems(m_nodeGroup);
        while ( iter.hasNext() ) {
            VisualItem item = (VisualItem)iter.next();
            ForceItem fitem = (ForceItem)item.get(FORCEITEM);
            fitem.mass = getMassValue(item);
            double x = item.getEndX();
            double y = item.getEndY();
            fitem.location[0] = (Double.isNaN(x) ? startX : (float)x);
            fitem.location[1] = (Double.isNaN(y) ? startY : (float)y);
            fsim.addItem(fitem);
        }
        if ( m_edgeGroup != null ) {
            iter = m_vis.visibleItems(m_edgeGroup);
            while ( iter.hasNext() ) {
                EdgeItem  e  = (EdgeItem)iter.next();
                NodeItem  n1 = e.getSourceItem();
                ForceItem f1 = (ForceItem)n1.get(FORCEITEM);
                NodeItem  n2 = e.getTargetItem();
                ForceItem f2 = (ForceItem)n2.get(FORCEITEM);
                float coeff = getSpringCoefficient(e);
                float slen = getSpringLength(e);
                fsim.addSpring(f1, f2, (coeff>=0?coeff:-1.f), (slen>=0?slen:-1.f));
            }
        }
    }
    
    /**
     * Get the mass value associated with the given node. Subclasses should
     * override this method to perform custom mass assignment.
     * @param n the node for which to compute the mass value
     * @return the mass value for the node. By default, all items are given
     * a mass value of 1.0.
     */
    protected float getMassValue(VisualItem n) {
        return 1.0f;
    }
    
    /**
     * Get the spring length for the given edge. Subclasses should
     * override this method to perform custom spring length assignment.
     * @param e the edge for which to compute the spring length
     * @return the spring length for the edge. A return value of
     * -1 means to ignore this method and use the global default.
     */
    protected float getSpringLength(EdgeItem e) {
        if (e.getString(CT.EDGE_FIELD_TYPE).equals(CT.EDGE_TYPE_ORG_TO_ORG))
            return 800f;
        return -1f;
    }

    /**
     * Get the spring coefficient for the given edge, which controls the
     * tension or strength of the spring. Subclasses should
     * override this method to perform custom spring tension assignment.
     * @param e the edge for which to compute the spring coefficient.
     * @return the spring coefficient for the edge. A return value of
     * -1 means to ignore this method and use the global default.
     */
    protected float getSpringCoefficient(EdgeItem e) {
        return -1.0f;
    }
    
    /**
     * Get the referrer item to use to set x or y coordinates that are
     * initialized to NaN.
     * @return the referrer item.
     * @see prefuse.util.PrefuseLib#setX(VisualItem, VisualItem, double)
     * @see prefuse.util.PrefuseLib#setY(VisualItem, VisualItem, double)
     */
    public VisualItem getReferrer() {
        return referrer;
    }
    
    /**
     * Set the referrer item to use to set x or y coordinates that are
     * initialized to NaN.
     * @param referrer the referrer item to use.
     * @see prefuse.util.PrefuseLib#setX(VisualItem, VisualItem, double)
     * @see prefuse.util.PrefuseLib#setY(VisualItem, VisualItem, double)
     */
    public void setReferrer(VisualItem referrer) {
        this.referrer = referrer;
    }
    
    // ------------------------------------------------------------------------
    // ForceItem Schema Addition
    
    /**
     * The data field in which the parameters used by this layout are stored.
     */
    public static final String FORCEITEM = "_forceItem";
    /**
     * The schema for the parameters used by this layout.
     */
    public static final Schema FORCEITEM_SCHEMA = new Schema();
    static {
        FORCEITEM_SCHEMA.addColumn(FORCEITEM,
                                   ForceItem.class,
                                   new ForceItem());
    }
    
} // end of class MyLayout
