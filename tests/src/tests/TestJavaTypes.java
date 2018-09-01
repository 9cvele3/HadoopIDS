package tests;


import org.junit.Test;
import org.junit.Assert;

public class TestJavaTypes {

	@Test
	public void test()
	{
		int i = 0xaa;
		byte b = (byte)i;
		Assert.assertEquals(127, b);
	}
}