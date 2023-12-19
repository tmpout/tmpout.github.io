.PHONY: demo
demo: clean
	mkdir -p demo
	mvn install
	cp ./demoSource/Main.java ./demo
	cp ./target/HandJar.B*.jar demo/
	cd demo && javac Main.java
	cd demo && jar -cfe vic.jar Main Main.class
	rm demo/*.java demo/*.class
	cd demo && java -jar HandJar.B*.jar
	@echo 'demo/vic.jar is infected'
	@echo 'to validate, run:'
	@echo 'java -jar demo/vic.jar'

.PHONY: clean
clean:
	rm -rf demo
	mvn clean
