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
	
	@Test
	public void testAssert()
	{
		assert 0 == 1;
	}
	
	@Test
	public void testConvert()
	{
		int x = 0x0800;
		Assert.assertEquals(256 * 8, x);
	}
}