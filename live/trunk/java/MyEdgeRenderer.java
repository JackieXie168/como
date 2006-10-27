import prefuse.Constants;
import prefuse.render.EdgeRenderer;
import prefuse.visual.EdgeItem;
import prefuse.visual.VisualItem;
import prefuse.util.ColorLib;
import java.awt.Graphics2D;

public class MyEdgeRenderer extends EdgeRenderer {
    protected double totalVolume;
    protected final double maxWidth = 20;

    public MyEdgeRenderer() {
        super();
        setEdgeType(Constants.EDGE_TYPE_CURVE);
    }
    public void setTotalVolume(int v)
    {
        totalVolume = v;
    }

    protected double getLineWidth(VisualItem item)
    {
        if (item.getString(CT.EDGE_FIELD_TYPE).equals(CT.EDGE_TYPE_TRANSMITTER_TO_TRANSMITTER)) {
            double d = (new Double(item.getString(CT.EDGE_FIELD_VOLUME))).doubleValue();
            return maxWidth * d / totalVolume;
        }
        return getDefaultLineWidth();
    }

    protected void getCurveControlPoints(EdgeItem eitem, java.awt.geom.Point2D[] cp, double x1, double y1, double x2, double y2)
    {
        super.getCurveControlPoints(eitem, cp, x1, y1, x2, y2);
    }

    public void render(Graphics2D g, VisualItem item)
    {
        boolean switched = false;
        int type = 0;
        String t = item.getString(CT.EDGE_FIELD_TYPE);

        if (t.equals(CT.EDGE_TYPE_ORG_TO_ORG))
            return;

        if (t.equals(CT.EDGE_TYPE_ORG_TO_TRANSMITTER)) {
            switched = true;
            type = getArrowType();
            setArrowType(Constants.EDGE_ARROW_NONE);
        }

        if (item.getString(CT.EDGE_FIELD_INTERESTING).equals(CT.EDGE_INTERESTING_YES))
            updateColor(item, 200, 0, 0);
        else
            updateColor(item, 200, 200, 200);

        super.render(g, item);

        if (switched) {
            setArrowType(type);
        }
    }

    protected void updateColor(VisualItem vi, int r, int g, int b)
    {
        vi.setStrokeColor(ColorLib.rgb(r, g, b));
        vi.setFillColor(ColorLib.rgb(r, g, b));
    }
}
