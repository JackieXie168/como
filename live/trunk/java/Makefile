JAVAC=CLASSPATH=.:prefuse.jar javac
CLASSES=ConversationView.class ConversationGraphContainer.class MyLayout.class MyEdgeRenderer.class CT.class

pack.jar: $(CLASSES)
	rm -f pack.jar
	jar cvf pack.jar *.class

%.class: %.java
	$(JAVAC) $<

clean:
	rm *.class pack.jar
