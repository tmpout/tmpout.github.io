.PHONY: demo
demo: clean
	mkdir -p demo
	mvn install
	cp ./demoSource/*.java ./demo
	cp ./target/ClassWar*.jar demo/
	cd demo && javac Util.java
	cd demo && jar -cf util.jar Util.class Util*.class
	cd demo && java -jar ClassWar*.jar
	cd demo && javac Main.java Util.java
	cd demo && jar -cfe vic.jar Main Main.class
	rm demo/*.java demo/*.class
	@echo 'demo/util.jar is infected'
	@echo 'to validate, run'
	@echo 'java -cp ./demo/util.jar:./demo/vic.jar Main'

.PHONY: clean
clean:
	rm -rf demo
	mvn clean
