package tests;


import org.junit.Test;
import org.junit.Assert;

public class TestJavaTypes {

	@Test
	public void test()
	{
		byte b = -18;
		
		char c = (char) b;
		Assert.assertEquals(127, c);
	}
}
